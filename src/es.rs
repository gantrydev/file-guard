//! macOS Endpoint Security client.
//!
//! Subscribes to ES_EVENT_TYPE_AUTH_OPEN on watched credential files.
//! For each open attempt the policy engine decides allow/deny; the ES
//! response is sent back before the kernel deadline.

use std::ffi::CString;
use std::path::PathBuf;
use std::sync::Arc;

use crate::logging::AccessLogger;
use crate::policy::engine::PolicyEngine;

// ── Endpoint Security C types ───────────────────────────────────────

// Opaque client handle.
#[repr(C)]
pub struct es_client_t {
    _opaque: [u8; 0],
}

// Subset of es_event_type_t we care about.
#[allow(non_camel_case_types)]
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum es_event_type_t {
    ES_EVENT_TYPE_AUTH_OPEN = 0,
}

// Audit token - 8 × u32, used to extract pid.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct audit_token_t {
    pub val: [u32; 8],
}

impl audit_token_t {
    /// PID lives at index 5 of the audit token.
    pub fn pid(&self) -> u32 {
        self.val[5]
    }
}

// es_string_token_t - pointer + length, NOT null-terminated.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct es_string_token_t {
    pub length: usize,
    pub data: *const u8,
}

impl es_string_token_t {
    pub fn as_str(&self) -> &str {
        if self.data.is_null() || self.length == 0 {
            return "";
        }
        unsafe {
            let slice = std::slice::from_raw_parts(self.data, self.length);
            std::str::from_utf8_unchecked(slice)
        }
    }
}

// Minimal es_file_t - we only need the path.
#[repr(C)]
pub struct es_file_t {
    pub path: es_string_token_t,
    pub path_truncated: bool,
}

// Minimal es_process_t.
#[repr(C)]
pub struct es_process_t {
    pub audit_token: audit_token_t,
    pub ppid: i32,
    pub original_ppid: i32,
    pub group_id: i32,
    pub session_id: i32,
    pub codesigning_flags: u32,
    pub is_platform_binary: bool,
    pub is_es_client: bool,
    pub cdhash: [u8; 20],
    pub signing_id: es_string_token_t,
    pub team_id: es_string_token_t,
    pub executable: *const es_file_t,
}

// es_event_open_t - the AUTH_OPEN payload.
#[repr(C)]
pub struct es_event_open_t {
    pub fflag: i32,
    pub file: *const es_file_t,
}

// es_events_t - union of event payloads. We only handle open.
#[repr(C)]
pub union es_events_t {
    pub open: std::mem::ManuallyDrop<es_event_open_t>,
}

// es_message_t - the top-level message delivered to our handler.
#[repr(C)]
pub struct es_message_t {
    pub version: u32,
    pub time: libc::timespec,
    pub mach_time: u64,
    pub deadline: u64,
    pub process: *const es_process_t,
    pub seq_num: u64,
    pub action_type: u32, // 0 = auth, 1 = notify
    pub event_type: es_event_type_t,
    pub event: es_events_t,
    // ... more fields we don't need
}

// Auth response values.
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum es_auth_result_t {
    ES_AUTH_RESULT_ALLOW = 0,
    ES_AUTH_RESULT_DENY = 1,
}

#[allow(non_camel_case_types)]
#[repr(i32)]
pub enum es_return_t {
    ES_RETURN_SUCCESS = 0,
    ES_RETURN_ERROR = 1,
}

#[allow(non_camel_case_types)]
#[repr(i32)]
#[derive(Debug, Clone, Copy)]
pub enum es_new_client_result_t {
    ES_NEW_CLIENT_RESULT_SUCCESS = 0,
}

// ── Endpoint Security FFI ───────────────────────────────────────────

type EsHandler = unsafe extern "C" fn(client: *mut es_client_t, message: *const es_message_t);

unsafe extern "C" {
    fn es_new_client(client: *mut *mut es_client_t, handler: EsHandler) -> es_new_client_result_t;

    fn es_delete_client(client: *mut es_client_t) -> es_return_t;

    fn es_subscribe(
        client: *mut es_client_t,
        events: *const es_event_type_t,
        event_count: u32,
    ) -> es_return_t;

    fn es_unsubscribe(
        client: *mut es_client_t,
        events: *const es_event_type_t,
        event_count: u32,
    ) -> es_return_t;

    fn es_respond_auth_result(
        client: *mut es_client_t,
        message: *const es_message_t,
        result: es_auth_result_t,
        cache: bool,
    ) -> es_return_t;

    fn es_mute_path(
        client: *mut es_client_t,
        path: *const libc::c_char,
        path_type: u32, // es_mute_path_type_t: 0 = prefix, 1 = literal
    ) -> es_return_t;

    fn es_invert_muting(
        client: *mut es_client_t,
        mute_type: u32, // es_mute_inversion_type_t: 0 = path, 1 = process
    ) -> es_return_t;

    fn es_mute_path_events(
        client: *mut es_client_t,
        path: *const libc::c_char,
        path_type: u32,
        events: *const es_event_type_t,
        event_count: usize,
    ) -> es_return_t;

    fn es_unmute_all_paths(client: *mut es_client_t) -> es_return_t;
}

// ── Public API ──────────────────────────────────────────────────────

/// Shared context passed into the ES handler via a global.
/// Safety: ES delivers messages on a serial queue so concurrent access
/// to the client pointer is safe. The policy engine is internally
/// synchronized.
struct HandlerContext {
    client: *mut es_client_t,
    watched_paths: Vec<PathBuf>,
    policy: Arc<PolicyEngine>,
    logger: Arc<AccessLogger>,
    rt_handle: tokio::runtime::Handle,
}

// ES handler callback requires a static context.
unsafe impl Send for HandlerContext {}
unsafe impl Sync for HandlerContext {}

static CONTEXT: std::sync::OnceLock<HandlerContext> = std::sync::OnceLock::new();

/// The ES handler invoked for every AUTH_OPEN on a watched path.
unsafe extern "C" fn handle_event(_client: *mut es_client_t, message: *const es_message_t) {
    let Some(ctx) = CONTEXT.get() else { return };
    let msg = unsafe { &*message };

    // Extract the file path being opened.
    let file_path = unsafe {
        let open = &msg.event.open;
        let file = &*open.file;
        PathBuf::from(file.path.as_str())
    };

    // Only enforce on watched paths; muting should already exclude the rest.
    if !ctx.watched_paths.iter().any(|w| *w == file_path) {
        unsafe {
            es_respond_auth_result(
                ctx.client,
                message,
                es_auth_result_t::ES_AUTH_RESULT_ALLOW,
                false,
            );
        }
        return;
    }

    // Extract process info from the ES message.
    let process = unsafe { &*msg.process };
    let pid = process.audit_token.pid();

    // TODO: derive the real direction from `msg.event.open.fflag`, which is
    // encoded with the in-kernel FREAD/FWRITE bits, NOT `O_RDONLY`/`O_WRONLY`,
    // so `Access::from_open_flags` would misclassify it. Until then every open
    // is gated with a single read-style decision.
    let access = crate::policy::rule::Access::Read;

    let result = match crate::process::identify::identify(pid) {
        Ok(info) => {
            let decision = ctx
                .rt_handle
                .block_on(ctx.policy.evaluate(&info, &file_path, access));

            ctx.logger.log(&info, &file_path, access, &decision, None);
            decision.is_allowed()
        }
        Err(e) => {
            tracing::warn!("failed to identify pid {pid}: {e}");
            false
        }
    };

    let auth = if result {
        es_auth_result_t::ES_AUTH_RESULT_ALLOW
    } else {
        es_auth_result_t::ES_AUTH_RESULT_DENY
    };

    unsafe {
        es_respond_auth_result(ctx.client, message, auth, false);
    }
}

/// RAII wrapper around the ES client lifetime.
pub struct EsClient {
    client: *mut es_client_t,
}

unsafe impl Send for EsClient {}

impl EsClient {
    /// Create a new ES client, subscribe to AUTH_OPEN, and mute everything
    /// except the watched paths.
    pub fn new(
        watched_paths: Vec<PathBuf>,
        policy: Arc<PolicyEngine>,
        logger: Arc<AccessLogger>,
        rt_handle: tokio::runtime::Handle,
    ) -> anyhow::Result<Self> {
        let mut client: *mut es_client_t = std::ptr::null_mut();

        let rc = unsafe { es_new_client(&mut client, handle_event) };
        if rc as i32 != es_new_client_result_t::ES_NEW_CLIENT_RESULT_SUCCESS as i32 {
            anyhow::bail!(
                "es_new_client failed (rc={:?}). Run as root with ES entitlement.",
                rc as i32
            );
        }

        // Mute all paths, then invert → only unmuted (watched) paths deliver events.
        unsafe {
            let root = CString::new("/").unwrap();
            es_mute_path(client, root.as_ptr(), 0 /* prefix */);
            es_invert_muting(client, 0 /* path muting */);
        }

        // Unmute each watched path so events are delivered for them.
        let events = [es_event_type_t::ES_EVENT_TYPE_AUTH_OPEN];
        for path in &watched_paths {
            let cpath = CString::new(path.to_string_lossy().as_bytes())
                .map_err(|_| anyhow::anyhow!("invalid path: {}", path.display()))?;
            unsafe {
                es_mute_path_events(
                    client,
                    cpath.as_ptr(),
                    1, // literal
                    events.as_ptr(),
                    events.len(),
                );
            }
        }

        // Store context for the handler.
        CONTEXT
            .set(HandlerContext {
                client,
                watched_paths,
                policy,
                logger,
                rt_handle,
            })
            .map_err(|_| anyhow::anyhow!("ES handler context already initialized"))?;

        // Subscribe to AUTH_OPEN.
        let rc = unsafe { es_subscribe(client, events.as_ptr(), events.len() as u32) };
        if rc as i32 != es_return_t::ES_RETURN_SUCCESS as i32 {
            anyhow::bail!("es_subscribe failed");
        }

        tracing::info!("Endpoint Security client started");
        Ok(Self { client })
    }
}

impl Drop for EsClient {
    fn drop(&mut self) {
        if !self.client.is_null() {
            unsafe {
                let events = [es_event_type_t::ES_EVENT_TYPE_AUTH_OPEN];
                es_unsubscribe(self.client, events.as_ptr(), events.len() as u32);
                es_unmute_all_paths(self.client);
                es_delete_client(self.client);
            }
            tracing::info!("Endpoint Security client stopped");
        }
    }
}

// ── Interceptor adapter ──────────────────────────────────────────

use crate::interceptor::{Interceptor, InterceptorArgs};

pub struct EsInterceptor {
    args: Option<InterceptorArgs>,
    client: Option<EsClient>,
}

impl EsInterceptor {
    pub fn new(args: InterceptorArgs) -> Self {
        Self {
            args: Some(args),
            client: None,
        }
    }
}

impl Interceptor for EsInterceptor {
    fn start(&mut self) -> anyhow::Result<()> {
        let args = self
            .args
            .take()
            .ok_or_else(|| anyhow::anyhow!("EsInterceptor already started"))?;

        let es = EsClient::new(args.watched_paths, args.policy, args.logger, args.rt_handle)?;
        self.client = Some(es);

        Ok(())
    }

    fn stop(&mut self) -> anyhow::Result<()> {
        self.client.take();

        Ok(())
    }
}
