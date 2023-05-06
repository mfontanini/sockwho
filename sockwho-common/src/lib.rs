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
    pub return_value: i32,
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
