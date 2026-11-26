//! The one read of secret bytes, nameable only by a crate that depends on this one.
#![no_std]

/// Reads the bytes a secret type guards.
pub trait Expose {
    /// The bytes the type guards.
    type Bytes: ?Sized;

    /// Borrows the guarded bytes.
    fn expose(&self) -> &Self::Bytes;
}
