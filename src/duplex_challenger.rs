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
    pub permutation: P,
    pub sponge_state: [F; WIDTH],
    pub has_sampled: bool,
}

impl<F: PrimeField64, P: CryptographicPermutation<[F; WIDTH]>> DuplexChallenger<F, P> {
    pub fn new(permutation: P) -> Self
    where
        F: Default,
    {
        Self {
            permutation,
            sponge_state: [F::ZERO; WIDTH],
            has_sampled: false,
        }
    }

    pub(crate) fn duplexing(&mut self, input_buffer: Option<[F; RATE]>) {
        if let Some(input_buffer) = input_buffer {
            for (i, val) in input_buffer.into_iter().enumerate() {
                self.sponge_state[i] = val;
            }
        }
        self.permutation.permute_mut(&mut self.sponge_state);
        self.has_sampled = false;
    }

    pub fn observe(&mut self, value: [F; RATE]) {
        self.duplexing(Some(value));
    }

    pub fn sample(&mut self) -> [F; RATE] {
        assert!(
            !self.has_sampled,
            "Cannot sample twice without duplexing in between"
        );
        self.has_sampled = true;
        self.sponge_state[..RATE].try_into().unwrap()
    }

    /// Warning: not perfectly uniform
    pub fn sample_in_range(&mut self, bits: usize, mut n_samples: usize) -> Vec<usize> {
        assert!(bits < F::bits());
        let mut samples = Vec::with_capacity(n_samples);
        loop {
            let chunks = self.sample();
            for &chunk in &chunks {
                let rand_usize = chunk.as_canonical_u64() as usize;
                samples.push(rand_usize & ((1 << bits) - 1));
                n_samples -= 1;
                if n_samples == 0 {
                    return samples;
                }
            }
            self.duplexing(None);
        }
    }
}
