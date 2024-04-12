use halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ProvingKey, VerifyingKey,
    },
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
        },
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
    SerdeFormat,
};

use base64::prelude::*;
use eyre::Result;
use halo2_backend::plonk::circuit::ConstraintSystemBack;
use halo2_proofs::poly::kzg::strategy::SingleStrategy;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
pub use halo2_proofs::halo2curves::bn256::Fr as F;

struct Keys {
    pk: ProvingKey<G1Affine>,
    general_params: ParamsKZG<Bn256>,
}

impl Keys {
    pub fn serialize(&self) -> Result<String> {
        let mut pk_ser: Vec<u8> = Vec::new();
        self.pk
            .write(&mut pk_ser, halo2_proofs::SerdeFormat::RawBytes)?;

        let mut general_params_ser: Vec<u8> = Vec::new();
        self.general_params
            .write_custom(&mut general_params_ser, SerdeFormat::RawBytes)?;

        let all = (self.pk.get_vk().cs(), pk_ser, general_params_ser);

        let serialized = bincode::serialize(&all)?;

        Ok(BASE64_STANDARD_NO_PAD.encode(serialized))
    }

    fn deserialize(encoded: &str) -> Result<Self> {
        let encoded = BASE64_STANDARD_NO_PAD.decode(encoded)?;

        let (cs, pk_ser, general_params_ser): (ConstraintSystemBack<F>, Vec<u8>, Vec<u8>) =
            bincode::deserialize(&encoded[..])?;

        let pk = ProvingKey::<G1Affine>::read(&mut &pk_ser[..], SerdeFormat::RawBytes, cs)?;

        let general_params = ParamsKZG::<Bn256>::read_custom(
            &mut &general_params_ser[..],
            SerdeFormat::RawBytes,
        )?;

        Ok(Self { pk, general_params })
    }
}

pub trait TestCircuit {
    type CIRCUIT : Circuit<F>;
    fn public_inputs() -> Vec<Vec<F>>;
    fn circuit_with_witness() -> Self::CIRCUIT;
    fn k() -> u32;
}

pub fn gen_keys<C>() -> Result<String>
where
    C: Circuit<F> + TestCircuit,
{
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let general_params = ParamsKZG::<Bn256>::setup(C::k(), &mut rng);

    let circuit = C::circuit_with_witness();

    let vk: VerifyingKey<G1Affine> =
        keygen_vk(&general_params, &circuit).expect("keygen_vk should not fail");

    let pk =
        keygen_pk(&general_params, vk.clone(), &circuit).expect("keygen_pk should not fail");

    Ok(Keys { pk, general_params }.serialize()?)
}

pub fn prove<C>(k: &str) -> Result<String>
where
    C: Circuit<F> + TestCircuit<CIRCUIT=C>,
{
    let keys = Keys::deserialize(k)?;

    let circuit : C = C::circuit_with_witness();
    let public_inputs = C::public_inputs();

    let public_inputs_ref = public_inputs
        .iter()
        .map(|x| x.as_slice())
        .collect::<Vec<_>>();

    let rng = ChaCha20Rng::seed_from_u64(42);

    // Create a proof
    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);

    // Bench proof generation time
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        ChaCha20Rng,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        C,
    >(
        &keys.general_params,
        &keys.pk,
        &[circuit],
        &[&public_inputs_ref],
        rng,
        &mut transcript,
    )
    .unwrap();

    let proof = transcript.finalize();

    Ok(BASE64_STANDARD_NO_PAD.encode(proof))
}

pub fn verify<C>(keys: &str, proof: &str) -> Result<bool>
where
    C: Circuit<F> + TestCircuit + Default,
{
    let keys = Keys::deserialize(keys)?;
    let proof = BASE64_STANDARD_NO_PAD.decode(proof)?;

    let mut verifier_transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof[..]);
    let strategy = SingleStrategy::new(&keys.general_params.verifier_params());

    let public_inputs = C::public_inputs();
    let public_inputs_ref = public_inputs
        .iter()
        .map(|x| x.as_slice())
        .collect::<Vec<_>>();

    let result = verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(
        &keys.general_params.verifier_params(),
        &keys.pk.get_vk(),
        strategy,
        &[&public_inputs_ref],
        &mut verifier_transcript,
    );
    println!("{:?}", result);
    Ok(result.is_ok())
}

pub fn mock_prover<C>() -> String
where
    C: Circuit<F> + TestCircuit + Default,
{
    use halo2_proofs::dev::MockProver;

    let circuit = C::circuit_with_witness();
    let public_inputs = C::public_inputs();

    let prover = MockProver::run(C::k(), &circuit, public_inputs).unwrap();
    format!("{:?}",prover.verify())
}
