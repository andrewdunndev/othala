/// The only way randomness enters any crate; the shells supply the OS source.
pub trait Entropy {
    /// Fills `out` with uniformly random bytes.
    fn fill(&mut self, out: &mut [u8]);
}

impl<E: Entropy + ?Sized> Entropy for &mut E {
    fn fill(&mut self, out: &mut [u8]) {
        todo!()
    }
}

/// Adapts any `rand_core` cryptographic generator into an [`Entropy`].
#[cfg(feature = "rand_core")]
#[derive(Debug)]
pub struct RandCore<R>(R);

#[cfg(feature = "rand_core")]
impl<R: rand_core::CryptoRng> RandCore<R> {
    /// Wraps a cryptographic generator.
    pub fn new(rng: R) -> Self {
        todo!()
    }
}

#[cfg(feature = "rand_core")]
impl<R: rand_core::CryptoRng> Entropy for RandCore<R> {
    fn fill(&mut self, out: &mut [u8]) {
        todo!()
    }
}
