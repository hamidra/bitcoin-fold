const NOVA_TARGET: &str = "layerX::bitfold";
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
    const ARITY: usize = 32;
    fn generate_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        i: &FpVar<F>,
        z: &[FpVar<F>],
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        // serialize the header to bytes
        let header_le_bytes = self.header.to_bytes();

        // allocate variables for the header bytes
        let allocated_header_bytes = UInt8::new_witness_vec(
            ark_relations::ns!(cs, "block header bytes"),
            &header_le_bytes,
        )?;

        // variables for previous block hash extracted from current block header
        let header_previous_hash = &allocated_header_bytes[4..36];

        // variables for previous block hash from IVC input (passed as IVC input z_{i-1})
        let mut input_previous_hash: Vec<UInt8<F>> = Vec::new();
        for fp in z {
            let bytes = fp.to_bytes()?;
            // take the 1st byte since the signature bytes are serialized in z in little-endian
            input_previous_hash.push(bytes[0].clone());
        }

        // enforce the previous block hash from block header to be equal with hash that is passed in input z_{i-1}.
        header_previous_hash.enforce_equal(&input_previous_hash)?;

        // ToDo: enforce the block hash is under target_bits difficulty

        // calculate and allocate block hash (bitcoin does double sha256 hash as sha256(sha256(header)) a.k.a sha256d)
        let header_digest = <Sha256Gadget<F> as CRHSchemeGadget<Sha256, F>>::evaluate(
            &UnitVar::default(),
            &allocated_header_bytes,
        )?;
        let digest_digest = <Sha256Gadget<F> as CRHSchemeGadget<Sha256, F>>::evaluate(
            &UnitVar::default(),
            &header_digest.0,
        )?;

        // convert digest to FpVar for z_out
        let mut z_out: Vec<FpVar<F>> = Vec::new();
        for byte in digest_digest.0 {
            // convert to FpVar for output
            // ToDo: find a better solution to convert UInt8 bytes directly to FpVar with no intermediate bit conversion
            let fp_var = Boolean::le_bits_to_fp_var(&byte.to_bits_le()?)?;
            z_out.push(fp_var);
        }

        //let previous_block_hash = z.
        Ok(z_out)
    }
}

#[cfg(test)]
pub(crate) mod bitcoin_fold_tests {
    use super::*;
    use crate::bitcoin::block_data::{self, BlockReader};
    use crate::bitcoin::data::test_json::TEST_JSON_RPC;
    use ark_crypto_primitives::crh::CRHScheme;
    use nexus_nova::circuits;

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
        // read a test block
        let block_reader = BlockReader::new_from_json(TEST_JSON_RPC).unwrap();
        let header = block_reader.get_block_header(838637).unwrap();

        let circuit = BitcoinHeaderCircuit::<G1::ScalarField> {
            header: header.clone(),
            _p: PhantomData,
        };

        let ro_config = poseidon_config();

        // pass in previous block hash
        let z_0: Vec<G1::ScalarField> = header
            .hash_prev_block
            .iter()
            .map(|byte| G1::ScalarField::from(byte.clone()))
            .collect();

        // run IVC for one step
        let num_steps = 1;

        println!("-> IVC started!");

        let params = PublicParams::<
            G1,
            G2,
            C1,
            C2,
            PoseidonSponge<G1::ScalarField>,
            BitcoinHeaderCircuit<G1::ScalarField>,
        >::setup(ro_config, &circuit, &(), &())?;
        println!("-> Setup is done!");

        let mut recursive_snark = IVCProof::new(&z_0);
        recursive_snark = recursive_snark.prove_step(&params, &circuit)?;
        println!("-> Proof is generated!");

        recursive_snark.verify(&params, num_steps).unwrap();
        println!("-> Proof is verified!");

        // check z_i is equal to the final block hash
        let header_digest = <Sha256 as CRHScheme>::evaluate(&(), header.to_bytes()).unwrap();
        let digest_digest = <Sha256 as CRHScheme>::evaluate(&(), header_digest).unwrap();
        let digest_digest_scalars: Vec<G1::ScalarField> = digest_digest
            .iter()
            .map(|byte| G1::ScalarField::from(byte.clone()))
            .collect();
        assert_eq!(recursive_snark.z_i(), digest_digest_scalars);

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
        // load headers data
        let block_reader = BlockReader::new_from_json(TEST_JSON_RPC).unwrap();
        let block_headers = block_reader.get_block_headers().unwrap();
        let block_headers: Vec<BitcoinHeader> = block_headers
            .into_iter()
            .map(|(_, header)| header)
            .collect();

        // create step circuits
        let mut step_circuits: Vec<BitcoinHeaderCircuit<G1::ScalarField>> = block_headers
            .iter()
            .map(|header| BitcoinHeaderCircuit {
                header: header.clone(),
                _p: PhantomData,
            })
            .collect();

        let ro_config = poseidon_config();

        // pass in previous block hash of the 1st block
        let z_0: Vec<G1::ScalarField> = block_headers[0]
            .hash_prev_block
            .iter()
            .map(|byte| G1::ScalarField::from(byte.clone()))
            .collect();

        let num_steps = block_headers.len();

        println!("-> IVC started!");

        let params = PublicParams::<
            G1,
            G2,
            C1,
            C2,
            PoseidonSponge<G1::ScalarField>,
            BitcoinHeaderCircuit<G1::ScalarField>,
        >::setup(ro_config, &step_circuits[0], &(), &())?;
        println!("-> Setup is done!");

        let mut recursive_snark = IVCProof::new(&z_0);

        for i in 0..num_steps {
            recursive_snark = IVCProof::prove_step(recursive_snark, &params, &step_circuits[i])?;
            println!("-> step {i} proof was folded!");
        }

        recursive_snark.verify(&params, num_steps).unwrap();
        println!("-> Folded Proof for steps 0->{num_steps} is verified!");

        let last_block_header = &block_headers[num_steps - 1];
        // check z_i is equal to the final block hash
        let header_digest =
            <Sha256 as CRHScheme>::evaluate(&(), last_block_header.to_bytes()).unwrap();
        let digest_digest = <Sha256 as CRHScheme>::evaluate(&(), header_digest).unwrap();
        let digest_digest_scalars: Vec<G1::ScalarField> = digest_digest
            .iter()
            .map(|byte| G1::ScalarField::from(byte.clone()))
            .collect();
        assert_eq!(recursive_snark.z_i(), digest_digest_scalars);

        Ok(())
    }
}

/*#[cfg(test)]
pub(crate) mod cubic_tests {

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
}*/
