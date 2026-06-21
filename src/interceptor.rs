use std::path::PathBuf;
use std::sync::Arc;

use crate::logging::AccessLogger;
use crate::policy::engine::PolicyEngine;
use crate::store::BackingStore;

pub struct InterceptorArgs {
    pub watched_paths: Vec<PathBuf>,
    pub policy: Arc<PolicyEngine>,
    pub logger: Arc<AccessLogger>,
    pub store: Arc<dyn BackingStore>,
    pub rt_handle: tokio::runtime::Handle,
    pub restore_on_stop: bool,
}

pub trait Interceptor: Send {
    fn start(&mut self) -> anyhow::Result<()>;
    fn stop(&mut self) -> anyhow::Result<()>;
}

pub fn create_interceptor(args: InterceptorArgs) -> anyhow::Result<Box<dyn Interceptor>> {
    #[cfg(target_os = "macos")]
    {
        let interceptor = crate::es::EsInterceptor::new(args);
        return Ok(Box::new(interceptor));
    }

    #[cfg(target_os = "linux")]
    {
        let interceptor = crate::fuse_fs::FuseInterceptor::new(args);
        Ok(Box::new(interceptor))
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        anyhow::bail!("unsupported platform");
    }
}
