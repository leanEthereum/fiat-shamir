use p3_field::ExtensionField;

use crate::{PF, ProofError, flatten_scalars_to_base, pack_scalars_to_extension};

pub trait ChallengeSampler<EF> {
    fn sample(&mut self) -> EF;
    fn sample_in_range(&mut self, bits: usize, n_samples: usize) -> Vec<usize>;

    fn sample_vec(&mut self, len: usize) -> Vec<EF> {
        (0..len).map(|_| self.sample()).collect()
    }
}

pub trait FSProver<EF: ExtensionField<PF<EF>>>: ChallengeSampler<EF> {
    fn state(&self) -> String;
    fn add_base_scalars(&mut self, scalars: &[PF<EF>]);
    fn pow_grinding(&mut self, bits: usize);
    fn hint_base_scalars(&mut self, scalars: &[PF<EF>]);

    fn add_extension_scalars(&mut self, scalars: &[EF]) {
        self.add_base_scalars(&flatten_scalars_to_base(scalars));
    }

    fn add_extension_scalar(&mut self, scalar: EF) {
        self.add_extension_scalars(&[scalar]);
    }

    fn hint_extension_scalars(&mut self, scalars: &[EF]) {
        self.hint_base_scalars(&flatten_scalars_to_base(scalars));
    }
}

pub trait FSVerifier<EF: ExtensionField<PF<EF>>>: ChallengeSampler<EF> {
    fn state(&self) -> String;
    fn next_base_scalars_vec(&mut self, n: usize) -> Result<Vec<PF<EF>>, ProofError>;
    fn receive_hint_base_scalars(&mut self, n: usize) -> Result<Vec<PF<EF>>, ProofError>;
    fn check_pow_grinding(&mut self, bits: usize) -> Result<(), ProofError>;

    fn next_base_scalars_const<const N: usize>(&mut self) -> Result<[PF<EF>; N], ProofError> {
        Ok(self.next_base_scalars_vec(N)?.try_into().unwrap())
    }

    fn next_extension_scalars_vec(&mut self, n: usize) -> Result<Vec<EF>, ProofError> {
        Ok(pack_scalars_to_extension(
            &self.next_base_scalars_vec(n * EF::DIMENSION)?,
        ))
    }

    fn next_extension_scalars_const<const N: usize>(&mut self) -> Result<[EF; N], ProofError> {
        Ok(self.next_extension_scalars_vec(N)?.try_into().unwrap())
    }

    fn next_extension_scalar(&mut self) -> Result<EF, ProofError> {
        Ok(self.next_extension_scalars_vec(1)?[0])
    }

    fn receive_hint_extension_scalars(&mut self, n: usize) -> Result<Vec<EF>, ProofError> {
        Ok(pack_scalars_to_extension(
            &self.receive_hint_base_scalars(n * EF::DIMENSION)?,
        ))
    }
}
