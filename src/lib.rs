const NOVA_TARGET: &str = "layerX::bitfold";
use std::marker::PhantomData;

mod bitcoin;
pub use bitcoin::BitcoinHeader;
use bitcoin::BlockReader;

// nova
use nexus_nova::{
    circuits::nova::{sequential::*, StepCircuit},
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

    fn bitcoin_fold_with_cycles<G1, G2, C1, C2>(
        header_chain: Vec<BitcoinHeader>,
    ) -> Result<(), Box<dyn Error>>
    where
        G1: SWCurveConfig,
        G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
        G1::BaseField: PrimeField + Absorb,
        G2::BaseField: PrimeField + Absorb,
        C1: CommitmentScheme<Projective<G1>, SetupAux = ()>,
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

        let params = PublicParams::<
            G1,
            G2,
            C1,
            C2,
            PoseidonSponge<G1::ScalarField>,
            BitcoinHeaderCircuit<G1::ScalarField>,
        >::setup(ro_config, &circuit_for_setup, &(), &())?;
        println!("-> Setup is done!");

        let mut recursive_snark: IVCProof<
            G1,
            G2,
            C1,
            C2,
            PoseidonSponge<<G1 as CurveConfig>::ScalarField>,
            BitcoinHeaderCircuit<<G1 as CurveConfig>::ScalarField>,
        > = IVCProof::new(&z_0);

        for (header) in header_chain.clone() {
            let circuit = BitcoinHeaderCircuit::<G1::ScalarField> {
                header: header,
                _p: PhantomData,
            };
            recursive_snark = recursive_snark.prove_step(&params, &circuit)?;
            println!("-> Proof is generated!");
        }

        recursive_snark.verify(&params, num_steps).unwrap();
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
        assert_eq!(recursive_snark.z_i(), digest_digest_scalars);

        Ok(())
    }

    #[test]
    fn bitcoin_fold_one_step() {
        // read a test block
        let block_reader = BlockReader::new_from_json(TEST_JSON_RPC).unwrap();
        let header = block_reader.get_block_header(838637).unwrap();
        bitcoin_fold_with_cycles::<
            ark_pallas::PallasConfig,
            ark_vesta::VestaConfig,
            PedersenCommitment<ark_pallas::Projective>,
            PedersenCommitment<ark_vesta::Projective>,
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
            ark_pallas::PallasConfig,
            ark_vesta::VestaConfig,
            PedersenCommitment<ark_pallas::Projective>,
            PedersenCommitment<ark_vesta::Projective>,
        >(block_headers)
        .unwrap()
    }
}
