pub mod identify;
pub mod integrity;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "linux")]
pub mod linux;

pub fn start_time(pid: u32) -> anyhow::Result<u64> {
    #[cfg(target_os = "linux")]
    return linux::start_time(pid);

    #[cfg(target_os = "macos")]
    return macos::start_time(pid);
}
