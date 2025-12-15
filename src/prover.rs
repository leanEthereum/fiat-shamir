use crate::{
    duplex_challenger::{DuplexChallenger, RATE, WIDTH},
    *,
};
use p3_field::Field;
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

impl<EF: ExtensionField<PF<EF>>, P: CryptographicPermutation<[PF<EF>; WIDTH]>> FSProver<EF>
    for ProverState<EF, P>
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

    // TODO SIMD
    fn pow_grinding(&mut self, bits: usize) {
        assert!(bits < PF::<EF>::bits());

        if bits == 0 {
            return;
        }

        let witness = (0..PF::<EF>::ORDER_U64)
            .into_par_iter()
            .map(|i| unsafe { PF::<EF>::from_canonical_unchecked(i) })
            .find_any(|witness| {
                let mut challenger_clone = self.challenger.clone();
                let mut value = [PF::<EF>::ZERO; RATE];
                value[0] = *witness;
                challenger_clone.observe(value);
                challenger_clone.sample_in_range(bits, 1)[0] == 0
            })
            .expect("failed to find witness");

        self.challenger.observe({
            let mut value = [PF::<EF>::ZERO; RATE];
            value[0] = witness;
            value
        });
        assert!(self.challenger.sample_in_range(bits, 1)[0] == 0);
        self.transcript.push(witness);
    }
}
