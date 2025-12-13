use crate::{
    duplex_challenger::{DuplexChallenger, RATE, WIDTH},
    *,
};
use p3_field::PrimeCharacteristicRing;
use p3_field::{ExtensionField, PrimeField64};
use p3_symmetric::CryptographicPermutation;

#[derive(Debug)]
pub struct VerifierState<EF: ExtensionField<PF<EF>>, P> {
    challenger: DuplexChallenger<PF<EF>, P>,
    transcript: Vec<PF<EF>>,
    index: usize,
    _extension_field: std::marker::PhantomData<EF>,
}

impl<EF: ExtensionField<PF<EF>>, P: CryptographicPermutation<[PF<EF>; WIDTH]>> VerifierState<EF, P>
where
    PF<EF>: PrimeField64,
{
    #[must_use]
    pub fn new(transcript: Vec<PF<EF>>, permutation: P) -> Self {
        assert!(EF::DIMENSION <= RATE);
        Self {
            challenger: DuplexChallenger::new(permutation),
            transcript,
            index: 0,
            _extension_field: std::marker::PhantomData,
        }
    }
}

impl<EF: ExtensionField<PF<EF>>, P: CryptographicPermutation<[PF<EF>; WIDTH]>> ChallengeSampler<EF>
    for VerifierState<EF, P>
where
    PF<EF>: PrimeField64,
{
    fn sample(&mut self) -> EF {
        EF::from_basis_coefficients_slice(&self.challenger.sample()[..EF::DIMENSION]).unwrap()
    }

    fn sample_bits(&mut self, bits: usize) -> usize {
        self.challenger.sample_bits(bits)
    }
}

impl<EF: ExtensionField<PF<EF>>, P: CryptographicPermutation<[PF<EF>; WIDTH]>> FSVerifier<EF>
    for VerifierState<EF, P>
where
    PF<EF>: PrimeField64,
{
    fn state(&self) -> String {
        format!("{:?}", self.challenger.sponge_state)
    }

    fn next_base_scalars_vec(&mut self, n: usize) -> Result<Vec<PF<EF>>, ProofError> {
        if n > self.transcript.len() - self.index {
            return Err(ProofError::ExceededTranscript);
        }
        let scalars = self.transcript[self.index..self.index + n].to_vec();
        self.index += n;

        for chunk in scalars.chunks(RATE) {
            let mut buffer = [PF::<EF>::ZERO; RATE];
            for (i, val) in chunk.iter().enumerate() {
                buffer[i] = *val;
            }
            self.challenger.observe(buffer);
        }

        Ok(scalars)
    }

    fn receive_hint_base_scalars(&mut self, n: usize) -> Result<Vec<PF<EF>>, ProofError> {
        if n > self.transcript.len() - self.index {
            return Err(ProofError::ExceededTranscript);
        }
        let scalars = self.transcript[self.index..self.index + n].to_vec();
        self.index += n;
        Ok(scalars)
    }

    fn check_pow_grinding(&mut self, bits: usize) -> Result<(), ProofError> {
        if bits == 0 {
            return Ok(());
        }

        if self.index + 1 > self.transcript.len() {
            return Err(ProofError::ExceededTranscript);
        }

        let witness = self.transcript[self.index];
        self.index += 1;

        self.challenger.observe({
            let mut value = [PF::<EF>::ZERO; RATE];
            value[0] = witness;
            value
        });
        if self.challenger.sample_bits(bits) != 0 {
            return Err(ProofError::InvalidGrindingWitness);
        }
        Ok(())
    }
}
