const NOVA_TARGET: &str = "layerX::bitfold";

// for profiling
use std::time::Instant;

use std::marker::PhantomData;

mod bitcoin;
pub use bitcoin::BitcoinHeader;
use bitcoin::BlockReader;

// nova
use ark_spartan::polycommitments::{zeromorph::Zeromorph, PolyCommitmentScheme};
use nexus_nova::{
    circuits::nova::{
        sequential::{compression::*, *},
        StepCircuit,
    },
    commitment::CommitmentScheme,
    pedersen::PedersenCommitment,
    poseidon_config,
};
use std::error::Error;

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
use ark_ec::{
    short_weierstrass::{Projective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::{AdditiveGroup, Field, PrimeField};
use ark_r1cs_std::{
    fields::{fp::FpVar, FieldVar},
    prelude::*,
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisError, SynthesisMode};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};

// ToDo: replace with a production ready crypto-rng
use ark_std::test_rng;

use ark_bn254::{g1::Config as Bn254Config, Bn254};
use ark_grumpkin::{GrumpkinConfig, Projective as GrumpkinProjective};

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

        Ok(z_out)
    }
}

/*pub struct ProofSerializer<G1, G2, C1, C2, RO, SC>(PhantomData<G1, G2, C1, C2, RO, SC>);

impl<G1, G2, C1, C2, RO, SC> ProofSerializer
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: CryptographicSponge + Send + Sync,
    RO::Config: CanonicalSerialize + CanonicalDeserialize + Sync,
    SC: StepCircuit<G1::ScalarField>,
{
    pub fn serialize_public_params(pp: PublicParams<G1, G2, C1, C2, RO, SC>) {
        let buffer = Vec::new();
        pp.serialize_compressed(&mut buffer);
        buffer
    }
    pub fn deserialize_public_params(
        bytes: Vec<u8>,
    ) -> Result<PublicParams<G1, G2, C1, C2, RO, SC>, SerializationError> {
        PublicParams::deserialize_compressed(&bytes[..])
    }

    pub fn serialize_proof(ivc_proof: IVCProof<G1, G2, C1, C2, RO, SC>) {
        let buffer = Vec::new();
        ivc_proof.serialize_compressed(buffer);
        buffer
    }

    pub fn deserialize_proof(
        bytes: Vec<u8>,
    ) -> Result<IVCProof<G1, G2, C1, C2, RO, SC>, SerializationError> {
        IVCProof::deserialize_compressed(&bytes[..])
    }
}*/

/*pub struct BitcoinIVC<G1, G2, C1, C2, RO, SC>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: CryptographicSponge + Send + Sync,
    RO::Config: CanonicalSerialize + CanonicalDeserialize + Sync,
    SC: StepCircuit<G1::ScalarField>,
{
    initial_height: usize,
    height: usize,
    params: PublicParams<G1, G2, C1, C2, RO, SC>,
    proof: IVCProof<G1, G2, C1, C2, RO, SC>,
}

impl BitcoinIVC<G1, G2, C1, C2, RO, SC> {
    pub fn setup(self) -> Self {
        self
    }
}*/

#[cfg(test)]
pub(crate) mod bitcoin_fold_tests {
    use super::*;
    use crate::bitcoin::data::test_json::TEST_JSON_RPC;
    use crate::bitcoin::BlockReader;
    use ark_crypto_primitives::crh::CRHScheme;
    use nexus_nova::circuits;

    fn setup_srs_params<G1, G2, PC, C2, RO, SC>(
        ro_config: RO::Config,
        step_circuit: &SC,
    ) -> (PC::SRS, PublicParams<G1, G2, PVC<G1, PC>, C2, RO, SC>)
    where
        G1: SWCurveConfig,
        G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
        G1::BaseField: PrimeField + Absorb,
        G2::BaseField: PrimeField + Absorb,
        PC: PolyCommitmentScheme<Projective<G1>>,
        PC::Commitment: Copy + Into<Projective<G1>> + From<Projective<G1>>,
        C2: CommitmentScheme<Projective<G2>, SetupAux = ()>,
        RO: SpongeWithGadget<G1::ScalarField> + Send + Sync,
        RO::Var: CryptographicSpongeVar<G1::ScalarField, RO, Parameters = RO::Config>,
        RO::Config: CanonicalSerialize + CanonicalDeserialize + Clone + Sync,
        SC: StepCircuit<G1::ScalarField>,
    {
        let mut rng = test_rng();

        let mut start = Instant::now();
        let (shape, _) = SetupParams::<(G1, G2, PVC<G1, PC>, C2, RO, SC)>::get_shape(
            ro_config.clone(),
            &step_circuit,
        )
        .unwrap();
        /*       println!("Extract_R1CS_SHAPE {} s", start.elapsed().as_secs());

                let min_num_vars = SNARKKey::<G1, PC>::get_min_srs_size(&shape).unwrap();
                println!("min_srs: {min_num_vars}");
        */

        // hardcoded min_num_vars, if circuit changes use commented code above to calculate the min required number.
        let min_num_vars = 25;

        let mut start = Instant::now();
        let srs = PC::setup(min_num_vars, b"test_srs", &mut rng).unwrap();
        println!("SETUP_SRS {} s", start.elapsed().as_secs());

        start = Instant::now();
        let params = PublicParams::<G1, G2, PVC<G1, PC>, C2, RO, SC>::setup(
            ro_config,
            &step_circuit,
            &srs,
            &(),
        )
        .expect("setup should not fail");
        println!("SETUP_PUBLIC_PARAMS {} s", start.elapsed().as_secs());

        (srs, params)
    }

    fn bitcoin_fold_with_cycles<G1, G2, PC, C2>(
        header_chain: Vec<BitcoinHeader>,
    ) -> Result<(), Box<dyn Error>>
    where
        G1: SWCurveConfig,
        G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
        G1::BaseField: PrimeField + Absorb,
        G2::BaseField: PrimeField + Absorb,
        PC: PolyCommitmentScheme<Projective<G1>>,
        PC::Commitment: Copy + Into<Projective<G1>> + From<Projective<G1>>,
        C2: CommitmentScheme<Projective<G2>, SetupAux = ()>,
    {
        let mut circuit_for_setup = BitcoinHeaderCircuit::<G1::ScalarField> {
            header: BitcoinHeader::default(),
            _p: PhantomData,
        };

        let ro_config = poseidon_config();

        // pass in previous block hash
        let z_0: Vec<G1::ScalarField> = header_chain[0]
            .hash_prev_block
            .iter()
            .map(|byte| G1::ScalarField::from(byte.clone()))
            .collect();

        // run IVC for one step
        let num_steps = header_chain.len();

        println!("-> IVC started!");
        let mut start = Instant::now();
        let (srs, params) = setup_srs_params::<
            G1,
            G2,
            PC,
            C2,
            PoseidonSponge<G1::ScalarField>,
            BitcoinHeaderCircuit<G1::ScalarField>,
        >(ro_config, &circuit_for_setup);
        println!("SETUP_SRS_PARAMS {} s", start.elapsed().as_secs());
        println!("-> Setup is done!");

        let mut nova_proof = IVCProof::new(&z_0);

        for (header) in header_chain.clone() {
            let circuit = BitcoinHeaderCircuit::<G1::ScalarField> {
                header: header,
                _p: PhantomData,
            };

            start = Instant::now();
            nova_proof = nova_proof.prove_step(&params, &circuit)?;
            println!("NOVA_PROOF {} s", start.elapsed().as_secs());

            println!("-> Proof is generated!");
        }

        start = Instant::now();
        nova_proof.verify(&params, num_steps).unwrap();
        println!("NOVA_PROOF_VERIFY {} s", start.elapsed().as_secs());
        println!("-> Proof is verified!");

        // check z_i is equal to the final block hash
        let header_digest =
            <Sha256 as CRHScheme>::evaluate(&(), header_chain[header_chain.len() - 1].to_bytes())
                .unwrap();
        let digest_digest = <Sha256 as CRHScheme>::evaluate(&(), header_digest).unwrap();
        let digest_digest_scalars: Vec<G1::ScalarField> = digest_digest
            .iter()
            .map(|byte| G1::ScalarField::from(byte.clone()))
            .collect();
        assert_eq!(nova_proof.z_i(), digest_digest_scalars);

        // compress IVCProof
        start = Instant::now();
        let key = SNARK::<
            G1,
            G2,
            PC,
            C2,
            PoseidonSponge<G1::ScalarField>,
            BitcoinHeaderCircuit<G1::ScalarField>,
        >::setup(&params, &srs)
        .unwrap();
        println!("SPARTAN_SETUP { } s", start.elapsed().as_secs());

        start = Instant::now();
        let compressed_nova_proof = SNARK::<
            G1,
            G2,
            PC,
            C2,
            PoseidonSponge<G1::ScalarField>,
            BitcoinHeaderCircuit<G1::ScalarField>,
        >::compress(&params, &key, nova_proof)
        .unwrap();
        println!("SPARTAN_PROOF { } s", start.elapsed().as_secs());

        // verify compressed proof.
        start = Instant::now();
        SNARK::<
            G1,
            G2,
            PC,
            C2,
            PoseidonSponge<G1::ScalarField>,
            BitcoinHeaderCircuit<G1::ScalarField>,
        >::verify(&key, &params, &compressed_nova_proof)
        .unwrap();
        println!("SPARTAN_VERIFY {}", start.elapsed().as_secs());

        Ok(())
    }

    #[test]
    fn bitcoin_fold_one_step() {
        // read a test block
        let block_reader = BlockReader::new_from_json(TEST_JSON_RPC).unwrap();
        let header = block_reader.get_block_header(838637).unwrap();
        bitcoin_fold_with_cycles::<
            Bn254Config,
            GrumpkinConfig,
            Zeromorph<Bn254>,
            PedersenCommitment<GrumpkinProjective>,
        >(vec![header])
        .unwrap();
    }

    #[test]
    fn bitcoin_fold_multiple_steps() {
        // load headers data
        let block_reader = BlockReader::new_from_json(TEST_JSON_RPC).unwrap();
        let block_headers = block_reader.get_block_headers().unwrap();
        let block_headers: Vec<BitcoinHeader> = block_headers
            .into_iter()
            .map(|(_, header)| header)
            .collect();

        bitcoin_fold_with_cycles::<
            Bn254Config,
            GrumpkinConfig,
            Zeromorph<Bn254>,
            PedersenCommitment<GrumpkinProjective>,
        >(block_headers)
        .unwrap()
    }
}
