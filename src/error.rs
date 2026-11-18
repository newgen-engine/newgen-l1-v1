// src/error.rs
//
// Step 2: base taxonomy per error handling "panic-free".
// Nota: modulo volutamente minimale.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    InvalidInput,
    RateLimited,
    Internal,
    StorageCorrupt,
    ProtocolMismatch,
    Unauthorized,
}

#[derive(Debug, Clone)]
pub struct NgError {
    pub kind: ErrorKind,
    pub msg: String,
}

impl NgError {
    pub fn new(kind: ErrorKind, msg: impl Into<String>) -> Self {
        Self {
            kind,
            msg: msg.into(),
        }
    }
    pub fn invalid(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidInput, msg)
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::Internal, msg)
    }
}

impl fmt::Display for NgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.msg)
    }
}

impl std::error::Error for NgError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_constructors_set_expected_kind() {
        let invalid = NgError::invalid("bad input");
        let internal = NgError::internal("boom");
        assert_eq!(invalid.kind, ErrorKind::InvalidInput);
        assert_eq!(internal.kind, ErrorKind::Internal);
    }

    #[test]
    fn display_includes_kind_and_message() {
        let err = NgError::new(ErrorKind::Unauthorized, "denied");
        let s = err.to_string();
        assert!(s.contains("Unauthorized"));
        assert!(s.contains("denied"));
    }
}
