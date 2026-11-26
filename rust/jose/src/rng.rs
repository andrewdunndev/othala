//! The caller's entropy as the generator `rsa` blinds, pads and salts with; private to this crate.
use core::convert::Infallible;

use base::Entropy;
use rand_core::{TryCryptoRng, TryRng};

pub(crate) struct Source<'a>(pub(crate) &'a mut dyn Entropy);

impl TryRng for Source<'_> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut bytes = [0; 4];
        self.0.fill(&mut bytes);
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut bytes = [0; 8];
        self.0.fill(&mut bytes);
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        self.0.fill(dst);
        Ok(())
    }
}

impl TryCryptoRng for Source<'_> {}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use base::Entropy;
    use rand_core::TryRng as _;

    use super::Source;

    struct Steps(u8);

    impl Entropy for Steps {
        fn fill(&mut self, out: &mut [u8]) {
            for byte in out {
                self.0 += 1;
                *byte = self.0;
            }
        }
    }

    #[test]
    fn draws_come_from_the_entropy_in_order() {
        let mut steps = Steps(0);
        let mut source = Source(&mut steps);
        assert_eq!(
            source.try_next_u32().ok(),
            Some(u32::from_le_bytes([1, 2, 3, 4]))
        );
        assert_eq!(
            source.try_next_u64().ok(),
            Some(u64::from_le_bytes([5, 6, 7, 8, 9, 10, 11, 12]))
        );
        let mut rest = [0; 3];
        assert!(source.try_fill_bytes(&mut rest).is_ok());
        assert_eq!(rest.to_vec(), Vec::from([13, 14, 15]));
    }
}
