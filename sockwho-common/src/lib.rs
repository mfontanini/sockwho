#![cfg_attr(not(feature = "user"), no_std)]

#[derive(Clone, Debug, Copy)]
#[repr(C)]
pub struct SockaddrEvent {
    pub pid: u32,
    pub fd: u32,
    pub address: [u8; 16],
    pub port: u16,
    pub family: AddressFamily,
    pub syscall: Syscall,
    pub errno: i32,
    pub command: [u8; 16],
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct SocketStateEvent {
    pub src_port: u16,
    pub dst_port: u16,
    pub family: AddressFamily,
    pub _padding: u8,
    pub old_state: u32,
    pub new_state: u32,
    pub pid: u32,
    pub src_address: [u8; 16],
    pub dst_address: [u8; 16],
    pub command: [u8; 16],
}

#[derive(Clone, Debug, Copy)]
#[repr(u8)]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Clone, Debug, Copy)]
#[cfg_attr(feature = "user", derive(Debug))]
#[repr(u8)]
pub enum Syscall {
    Bind,
    Connect,
    RecvFrom,
    SendTo,
}

pub struct HandlerError(i32);

impl HandlerError {
    pub fn into_error_code(self) -> i32 {
        self.0
    }
}

impl<T> From<T> for HandlerError
where
    i32: TryFrom<T>,
{
    fn from(value: T) -> Self {
        // Note: this loses the value but I don't really care about error codes.
        let value = i32::try_from(value).unwrap_or(1);
        Self(value)
    }
}

pub type HandlerResult = Result<(), HandlerError>;
