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

    /// Returns `RATE` uniformly random field elements from the sponge state.
    ///
    /// Each element is uniform in `[0, P)` where `P` is the field modulus.
    /// For KoalaBear (`P = 2^31 - 2^24 + 1`), values in `[P, 2^31)` are never
    /// output since the permutation operates over `F_p`. This is correct for
    /// generating field challenges — no bias exists within the field.
    pub fn sample(&mut self) -> [F; RATE] {
        assert!(
            !self.has_sampled,
            "Cannot sample twice without duplexing in between"
        );
        self.has_sampled = true;
        self.sponge_state[..RATE].try_into().unwrap()
    }

    /// Samples integers in `[0, 2^bits)` by masking field elements.
    ///
    /// **Bias analysis:** Each sample masks a uniform `[0, P)` field element to `bits` bits.
    /// For KoalaBear (`P = 2^31 - 2^24 + 1`):
    /// - `bits <= 24`: perfectly uniform — `P mod 2^b = 1` for all `b <= 24`, giving
    ///   each residue either `floor(P / 2^b)` or `ceil(P / 2^b)` hits (differ by 1).
    /// - `bits 25..30`: bias ≤ `2^bits / P < 1/2`, negligible for STIR query sampling.
    /// - `bits = 31`: excluded by `assert!(bits < F::bits())`.
    ///
    /// Used by WHIR's STIR queries where `bits = log2(folded_domain_size)`, typically ≤ 20.
    pub fn sample_in_range(&mut self, bits: usize, mut n_samples: usize) -> Vec<usize> {
        assert!(bits < F::bits());
        let mut samples = Vec::with_capacity(n_samples);
        loop {
            let chunks = self.sample();
            self.duplexing(None);
            for &chunk in &chunks {
                let rand_usize = chunk.as_canonical_u64() as usize;
                samples.push(rand_usize & ((1 << bits) - 1));
                n_samples -= 1;
                if n_samples == 0 {
                    return samples;
                }
            }
        }
    }
}
