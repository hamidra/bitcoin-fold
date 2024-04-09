const NOVA_TARGET: &str = "layerX::bitfold";
use std::fmt::Display;
use std::marker::PhantomData;

mod bitcoin;
use bitcoin::BitcoinHeader;
use nexus_nova::circuits::nova::sequential::*;
use nexus_nova::circuits::nova::*;
use nexus_nova::commitment::CommitmentScheme;
use nexus_nova::folding::nova::cyclefold;
use nexus_nova::{pedersen::PedersenCommitment, poseidon_config};

// ark
use ark_crypto_primitives::{
    crh::{
        self,
        sha256::{
            constraints::{Sha256Gadget, UnitVar},
            Sha256,
        },
        CRHSchemeGadget,
    },
    sponge::{
        constraints::{CryptographicSpongeVar, SpongeWithGadget},
        poseidon::PoseidonSponge,
        Absorb, CryptographicSponge,
    },
};
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::{AdditiveGroup, Field, PrimeField};
use ark_r1cs_std::{
    fields::{fp::FpVar, FieldVar},
    prelude::*,
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisError, SynthesisMode};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use tracing_subscriber::{
    filter, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
};

#[derive(Debug, Default)]
pub struct BitcoinHeaderCircuit<F: Field> {
    header: BitcoinHeader,
    _p: PhantomData<F>,
}

impl<F: PrimeField> StepCircuit<F> for BitcoinHeaderCircuit<F> {
    const ARITY: usize = 1;
    fn generate_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        i: &FpVar<F>,
        z: &[FpVar<F>],
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        // serialize the header to bytes
        let header_le_bytes = self.header.to_bytes();

        // allocate variables for the header in input
        let allocated_header_bytes = UInt8::new_witness_vec(
            ark_relations::ns!(cs, "block header bytes"),
            &header_le_bytes,
        )?;

        // variables for previous block hash extracted from current block header
        let header_previous_hash = &allocated_header_bytes[4..36];

        // variables for previous block hash from IVC input (passed as IVC input z_{i-1})
        let mut input_previous_hash: Vec<UInt8<F>> = Vec::new();
        for z_fp in z {
            let bytes = z_fp.to_bytes()?;
            input_previous_hash.push(bytes[0].clone());
        }
        // enforce the previous block hash from block header be equal with the hash that is passed as input.
        header_previous_hash.enforce_equal(&input_previous_hash)?;

        // ToDo: enforce the block hash is under target difficulty

        // calculate and allocate block hash
        let digest = <Sha256Gadget<F> as CRHSchemeGadget<Sha256, F>>::evaluate(
            &UnitVar::default(),
            &allocated_header_bytes,
        )?;

        // convert digest to z_{out}

        let mut z_out: Vec<FpVar<F>> = Vec::new();
        for byte in digest.0 {
            let fp_var = Boolean::le_bits_to_fp_var(&byte.to_bits_le()?)?;
            z_out.push(fp_var);
        }

        //let previous_block_hash = z.
        Ok(z_out)
    }
}

#[cfg(test)]
pub(crate) mod tests {

    use super::*;

    #[derive(Debug, Default)]
    pub struct CubicCircuit<F: Field>(PhantomData<F>);

    impl<F: PrimeField> StepCircuit<F> for CubicCircuit<F> {
        const ARITY: usize = 1;

        fn generate_constraints(
            &self,
            _: ConstraintSystemRef<F>,
            _: &FpVar<F>,
            z: &[FpVar<F>],
        ) -> Result<Vec<FpVar<F>>, SynthesisError> {
            assert_eq!(z.len(), 1);

            let x = &z[0];

            let x_square = x.square()?;
            let x_cube = x_square * x;

            let y: FpVar<F> = x + x_cube + &FpVar::Constant(5u64.into());

            Ok(vec![y])
        }
    }

    #[test]
    fn ivc_base_step() {
        ivc_base_step_with_cycle::<
            ark_pallas::PallasConfig,
            ark_vesta::VestaConfig,
            PedersenCommitment<ark_pallas::Projective>,
            PedersenCommitment<ark_vesta::Projective>,
        >()
        .unwrap()
    }

    fn ivc_base_step_with_cycle<G1, G2, C1, C2>() -> Result<(), cyclefold::Error>
    where
        G1: SWCurveConfig,
        G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
        G1::BaseField: PrimeField + Absorb,
        G2::BaseField: PrimeField + Absorb,
        C1: CommitmentScheme<Projective<G1>, SetupAux = ()>,
        C2: CommitmentScheme<Projective<G2>, SetupAux = ()>,
    {
        let ro_config = poseidon_config();

        let circuit = CubicCircuit::<G1::ScalarField>(PhantomData);
        let z_0 = vec![G1::ScalarField::ONE];
        let num_steps = 1;

        let params = PublicParams::<
            G1,
            G2,
            C1,
            C2,
            PoseidonSponge<G1::ScalarField>,
            CubicCircuit<G1::ScalarField>,
        >::setup(ro_config, &circuit, &(), &())?;

        let mut recursive_snark = IVCProof::new(&z_0);
        recursive_snark = recursive_snark.prove_step(&params, &circuit)?;
        recursive_snark.verify(&params, num_steps).unwrap();

        assert_eq!(&recursive_snark.z_i()[0], &G1::ScalarField::from(7));

        Ok(())
    }

    #[test]
    fn ivc_multiple_steps() {
        ivc_multiple_steps_with_cycle::<
            ark_pallas::PallasConfig,
            ark_vesta::VestaConfig,
            PedersenCommitment<ark_pallas::Projective>,
            PedersenCommitment<ark_vesta::Projective>,
        >()
        .unwrap()
    }

    fn ivc_multiple_steps_with_cycle<G1, G2, C1, C2>() -> Result<(), cyclefold::Error>
    where
        G1: SWCurveConfig,
        G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
        G1::BaseField: PrimeField + Absorb,
        G2::BaseField: PrimeField + Absorb,
        C1: CommitmentScheme<Projective<G1>, SetupAux = ()>,
        C2: CommitmentScheme<Projective<G2>, SetupAux = ()>,
    {
        let filter = filter::Targets::new().with_target(NOVA_TARGET, tracing::Level::DEBUG);
        let _guard = tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer().with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE),
            )
            .with(filter)
            .set_default();

        let ro_config = poseidon_config();

        let circuit = CubicCircuit::<G1::ScalarField>(PhantomData);
        let z_0 = vec![G1::ScalarField::ONE];
        let num_steps = 3;

        let params = PublicParams::<
            G1,
            G2,
            C1,
            C2,
            PoseidonSponge<G1::ScalarField>,
            CubicCircuit<G1::ScalarField>,
        >::setup(ro_config, &circuit, &(), &())?;

        let mut recursive_snark = IVCProof::new(&z_0);

        for _ in 0..num_steps {
            recursive_snark = IVCProof::prove_step(recursive_snark, &params, &circuit)?;
        }
        recursive_snark.verify(&params, num_steps).unwrap();

        assert_eq!(&recursive_snark.z_i()[0], &G1::ScalarField::from(44739235));
        Ok(())
    }
}
