/// The only way randomness enters any crate; the shells supply the OS source.
pub trait Entropy {
    /// Fills `out` with uniformly random bytes.
    fn fill(&mut self, out: &mut [u8]);
}

impl<E: Entropy + ?Sized> Entropy for &mut E {
    fn fill(&mut self, out: &mut [u8]) {
        (**self).fill(out);
    }
}

/// Adapts any `rand_core` cryptographic generator into an [`Entropy`].
#[cfg(feature = "rand_core")]
#[derive(Debug)]
pub struct RandCore<R>(R);

#[cfg(feature = "rand_core")]
impl<R: rand_core::CryptoRng> RandCore<R> {
    /// Wraps a cryptographic generator.
    pub const fn new(rng: R) -> Self {
        Self(rng)
    }
}

#[cfg(feature = "rand_core")]
impl<R: rand_core::CryptoRng> Entropy for RandCore<R> {
    fn fill(&mut self, out: &mut [u8]) {
        self.0.fill_bytes(out);
    }
}

#[cfg(test)]
mod tests {
    use super::Entropy;

    struct Ones;

    impl Entropy for Ones {
        fn fill(&mut self, out: &mut [u8]) {
            out.fill(1);
        }
    }

    #[test]
    fn a_borrowed_source_fills() {
        let mut out = [0u8; 2];
        let mut source = Ones;
        let mut borrowed: &mut dyn Entropy = &mut source;
        Entropy::fill(&mut borrowed, &mut out);
        assert_eq!(out, [1, 1]);
    }
}
