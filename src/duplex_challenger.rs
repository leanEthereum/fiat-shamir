use p3_field::PrimeField64;
use p3_symmetric::CryptographicPermutation;

// modified version of: https://github.com/Plonky3/Plonky3/blob/main/challenger/src/duplex_challenger.rs
// - same security
// - less efficient on real hardware
// - more efficient on leanVM

pub(crate) const WIDTH: usize = 16;
pub(crate) const RATE: usize = 8;

#[derive(Clone, Debug)]
pub struct DuplexChallenger<F, P> {
    pub sponge_state: [F; WIDTH],

    pub output_buffer: Option<[F; RATE]>,

    pub permutation: P,
}

impl<F: PrimeField64, P: CryptographicPermutation<[F; WIDTH]>> DuplexChallenger<F, P> {
    pub fn new(permutation: P) -> Self
    where
        F: Default,
    {
        Self {
            sponge_state: [F::default(); WIDTH],
            output_buffer: None,
            permutation,
        }
    }

    fn duplexing(&mut self, input_buffer: Option<[F; RATE]>) {
        if let Some(input_buffer) = input_buffer {
            for (i, val) in input_buffer.into_iter().enumerate() {
                self.sponge_state[i] = val;
            }
        }
        self.permutation.permute_mut(&mut self.sponge_state);
        self.output_buffer = Some(self.sponge_state[..RATE].try_into().unwrap());
    }

    pub fn observe(&mut self, value: [F; RATE]) {
        self.duplexing(Some(value));
    }

    pub fn sample(&mut self) -> [F; RATE] {
        if self.output_buffer.is_none() {
            self.duplexing(None);
        }
        self.output_buffer.take().unwrap()
    }

    /// Warning: not perfectly uniform
    pub fn sample_bits(&mut self, bits: usize) -> usize {
        assert!(bits < F::bits());
        let rand_usize = self.sample()[0].as_canonical_u64() as usize;
        rand_usize & ((1 << bits) - 1)
    }
}
