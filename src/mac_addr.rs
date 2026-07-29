//! Defines a convenience type for parsing and displaying media access control
//! (MAC) addresses.

use thiserror::Error;

/// Length of a MAC address
const MAC_LENGTH_BYTES: usize = 6;

//-----------------------------------------------------------------------------
/// MAC address parsing error
#[derive(Debug, Error)]
pub enum MacAddrError {
    #[error("expected length {MAC_LENGTH_BYTES}, found {0}")]
    InvalidLength(usize),
}

//-----------------------------------------------------------------------------
/// Media access control (MAC) address
#[derive(Clone, PartialEq)]
pub struct MacAddr {
    /// MAC address octets
    octets: [u8; MAC_LENGTH_BYTES],
}

impl TryFrom<Vec<u8>> for MacAddr {
    type Error = MacAddrError;

    fn try_from(octets: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self {
            octets: octets
                .try_into()
                .map_err(|err_vec: Vec<_>| MacAddrError::InvalidLength(err_vec.len()))?,
        })
    }
}

impl std::fmt::Display for MacAddr {
    /// Display the MAC address
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            fmt,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.octets[0],
            self.octets[1],
            self.octets[2],
            self.octets[3],
            self.octets[4],
            self.octets[5]
        )
    }
}
