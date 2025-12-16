use crate::{
    duplex_challenger::{DuplexChallenger, RATE, WIDTH},
    *,
};
use p3_field::Field;
use p3_field::PackedValue;
use p3_field::PrimeCharacteristicRing;
use p3_field::integers::QuotientMap;
use p3_field::{ExtensionField, PrimeField64};
use p3_symmetric::CryptographicPermutation;
use rayon::prelude::*;
use std::{fmt::Debug, iter::repeat_n};

#[derive(Debug)]
pub struct ProverState<EF: ExtensionField<PF<EF>>, P> {
    challenger: DuplexChallenger<PF<EF>, P>,
    transcript: Vec<PF<EF>>,
    n_zeros: usize,
    _extension_field: std::marker::PhantomData<EF>,
}

impl<EF: ExtensionField<PF<EF>>, P: CryptographicPermutation<[PF<EF>; WIDTH]>> ProverState<EF, P>
where
    PF<EF>: PrimeField64,
{
    #[must_use]
    pub fn new(permutation: P) -> Self {
        assert!(EF::DIMENSION <= RATE);
        Self {
            challenger: DuplexChallenger::new(permutation),
            transcript: Vec::new(),
            n_zeros: 0,
            _extension_field: std::marker::PhantomData,
        }
    }

    pub fn proof_size_fe(&self) -> usize {
        self.transcript.len() - self.n_zeros
    }

    pub fn proof(&self) -> &[PF<EF>] {
        &self.transcript
    }

    pub fn into_proof(self) -> Vec<PF<EF>> {
        self.transcript
    }
}

impl<EF: ExtensionField<PF<EF>>, P: CryptographicPermutation<[PF<EF>; WIDTH]>> ChallengeSampler<EF>
    for ProverState<EF, P>
where
    PF<EF>: PrimeField64,
{
    fn duplexing(&mut self) {
        self.challenger.duplexing(None);
    }

    fn sample(&mut self) -> EF {
        EF::from_basis_coefficients_slice(&self.challenger.sample()[..EF::DIMENSION]).unwrap()
    }

    fn sample_in_range(&mut self, bits: usize, n_samples: usize) -> Vec<usize> {
        self.challenger.sample_in_range(bits, n_samples)
    }
}

impl<
    EF: ExtensionField<PF<EF>>,
    P: CryptographicPermutation<[PF<EF>; WIDTH]>
        + CryptographicPermutation<[<PF<EF> as Field>::Packing; WIDTH]>,
> FSProver<EF> for ProverState<EF, P>
where
    PF<EF>: PrimeField64,
{
    fn add_base_scalars(&mut self, scalars: &[PF<EF>]) {
        let padding = scalars.len().next_multiple_of(RATE) - scalars.len();
        self.transcript.extend_from_slice(scalars);
        self.transcript.extend(repeat_n(PF::<EF>::ZERO, padding));
        self.n_zeros += padding;
        for chunk in scalars.chunks(RATE) {
            let mut buffer = [PF::<EF>::ZERO; RATE];
            for (i, val) in chunk.iter().enumerate() {
                buffer[i] = *val;
            }
            self.challenger.observe(buffer);
        }
    }

    fn state(&self) -> String {
        format!("{:?}", self.challenger.sponge_state)
    }

    fn hint_base_scalars(&mut self, scalars: &[PF<EF>]) {
        self.transcript.extend(scalars);
    }

    fn pow_grinding(&mut self, bits: usize) {
        assert!(bits < PF::<EF>::bits());

        if bits == 0 {
            return;
        }

        type Packed<EF> = <PF<EF> as Field>::Packing;
        let lanes = Packed::<EF>::WIDTH;

        // each batch tests lanes witnesses simultaneously
        let num_batches = (PF::<EF>::ORDER_U64 + lanes as u64 - 1) / lanes as u64;
        let witness = (0..num_batches)
            .into_par_iter()
            .find_any(|&batch| {
                let base = batch * lanes as u64;

                let packed_witnesses = Packed::<EF>::from_fn(|lane| {
                    let candidate = base + lane as u64;
                    if candidate < PF::<EF>::ORDER_U64 {
                        unsafe { PF::<EF>::from_canonical_unchecked(candidate) }
                    } else {
                        PF::<EF>::ZERO
                    }
                });

                let mut packed_state: [Packed<EF>; WIDTH] = std::array::from_fn(|i| {
                    if i == 0 {
                        packed_witnesses
                    } else if i < RATE {
                        Packed::<EF>::from(PF::<EF>::ZERO)
                    } else {
                        Packed::<EF>::from(self.challenger.sponge_state[i])
                    }
                });

                self.challenger.permutation.permute_mut(&mut packed_state);

                let samples = packed_state[0].as_slice();
                for sample in samples {
                    let rand_usize = sample.as_canonical_u64() as usize;
                    if (rand_usize & ((1 << bits) - 1)) == 0 {
                        return true;
                    }
                }
                false
            })
            .expect("failed to find witness");

        // winning batch to find exact witness
        let base = witness * lanes as u64;
        let packed_witnesses = Packed::<EF>::from_fn(|lane| {
            let candidate = base + lane as u64;
            if candidate < PF::<EF>::ORDER_U64 {
                unsafe { PF::<EF>::from_canonical_unchecked(candidate) }
            } else {
                PF::<EF>::ZERO
            }
        });

        let mut packed_state: [Packed<EF>; WIDTH] = std::array::from_fn(|i| {
            if i == 0 {
                packed_witnesses
            } else if i < RATE {
                Packed::<EF>::from(PF::<EF>::ZERO)
            } else {
                Packed::<EF>::from(self.challenger.sponge_state[i])
            }
        });
        self.challenger.permutation.permute_mut(&mut packed_state);

        let samples = packed_state[0].as_slice();
        let exact_witness = samples
            .iter()
            .enumerate()
            .find_map(|(lane, sample)| {
                let candidate = base + lane as u64;
                let rand_usize = sample.as_canonical_u64() as usize;
                if (rand_usize & ((1 << bits) - 1)) == 0 && candidate < PF::<EF>::ORDER_U64 {
                    Some(unsafe { PF::<EF>::from_canonical_unchecked(candidate) })
                } else {
                    None
                }
            })
            .expect("witness not found in batch");

        self.challenger.observe({
            let mut value = [PF::<EF>::ZERO; RATE];
            value[0] = exact_witness;
            value
        });
        assert!(self.challenger.sample_in_range(bits, 1)[0] == 0);
        self.transcript.push(exact_witness);
    }
}
