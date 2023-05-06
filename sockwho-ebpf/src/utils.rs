/// Converts a PID+TGID into what userspace considers a PID.
pub fn as_pid(pid_tgid: u64) -> u32 {
    (pid_tgid >> 32) as u32
}
