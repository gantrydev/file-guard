pub mod identify;
pub mod integrity;

#[cfg(target_os = "linux")]
pub mod linux;

pub fn start_time(pid: u32) -> anyhow::Result<u64> {
    #[cfg(target_os = "linux")]
    return linux::start_time(pid);

    #[cfg(not(target_os = "linux"))]
    anyhow::bail!("unsupported platform")
}
