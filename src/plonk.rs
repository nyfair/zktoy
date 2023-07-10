// codes borrowed from https://github.com/matter-labs/zksync
use bellman::bn256::Bn256;
use bellman::{
    kate_commitment::{Crs, CrsForLagrangeForm, CrsForMonomialForm},
    pairing::Engine,
    plonk::{
        better_cs::adaptor::TranspilationVariant,
        better_cs::cs::PlonkCsWidth4WithNextStepParams,
        better_cs::keys::{Proof, SetupPolynomials, VerificationKey},
        commitments::transcript::keccak_transcript::RollingKeccakTranscript,
        is_satisfied_using_one_shot_check, make_verification_key, prove, prove_by_steps, setup,
    },
    worker::Worker,
    Circuit, ScalarEngine, SynthesisError,
};
use crate::circom_circuit::CircomCircuit;
use crate::transpile::{transpile_with_gates_count, ConstraintStat, TranspilerWrapper};

type E = Bn256;

const SETUP_MIN_POW2: u32 = 10;
const SETUP_MAX_POW2: u32 = 26;

pub struct SetupForProver {
    setup_polynomials: SetupPolynomials<E, PlonkCsWidth4WithNextStepParams>,
    hints: Vec<(usize, TranspilationVariant)>,
    key_monomial_form: Crs<E, CrsForMonomialForm>,
    key_lagrange_form: Option<Crs<E, CrsForLagrangeForm>>,
}

// circuit analysis result
#[derive(serde::Serialize)]
pub struct AnalyseResult {
    pub num_inputs: usize,
    pub num_aux: usize,
    pub num_variables: usize,
    pub num_constraints: usize,
    pub num_nontrivial_constraints: usize,
    pub num_gates: usize,
    pub num_hints: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub constraint_stats: Vec<ConstraintStat>,
}

// analyse a circuit
pub fn analyse<E: Engine>(circuit: CircomCircuit<E>) -> Result<AnalyseResult, anyhow::Error> {
    let mut transpiler = TranspilerWrapper::<E, PlonkCsWidth4WithNextStepParams>::new();
    let mut result = AnalyseResult {
        num_inputs: circuit.r1cs.num_inputs,
        num_aux: circuit.r1cs.num_aux,
        num_variables: circuit.r1cs.num_variables,
        num_constraints: circuit.r1cs.constraints.len(),
        num_nontrivial_constraints: 0,
        num_gates: 0,
        num_hints: 0,
        constraint_stats: Vec::new(),
    };
    circuit
        .synthesize(&mut transpiler)
        .expect("sythesize into traspilation must succeed");
    result.num_nontrivial_constraints = transpiler.constraint_stats.len();
    result.num_gates = transpiler.num_gates();
    result.constraint_stats = transpiler.constraint_stats.clone();
    let hints = transpiler.into_hints();
    result.num_hints = hints.len();
    Ok(result)
}

impl SetupForProver {
    // meta-data preparation before proving a circuit
    pub fn prepare_setup_for_prover<C: Circuit<E> + Clone>(
        circuit: C,
        key_monomial_form: Crs<E, CrsForMonomialForm>,
        key_lagrange_form: Option<Crs<E, CrsForLagrangeForm>>,
    ) -> Result<Self, anyhow::Error> {
        let (_, hints) = transpile_with_gates_count(circuit.clone())?;
        let setup_polynomials = setup(circuit, &hints)?;
        let size = setup_polynomials.n.next_power_of_two().trailing_zeros();
        let setup_power_of_two = std::cmp::max(size, SETUP_MIN_POW2);
        anyhow::ensure!(
            (SETUP_MIN_POW2..=SETUP_MAX_POW2).contains(&setup_power_of_two),
            "setup power of two is not in the correct range"
        );

        Ok(SetupForProver {
            setup_polynomials,
            hints,
            key_monomial_form,
            key_lagrange_form,
        })
    }

    // generate a verification key for a circuit
    pub fn make_verification_key(&self) -> Result<VerificationKey<E, PlonkCsWidth4WithNextStepParams>, SynthesisError> {
        make_verification_key(&self.setup_polynomials, &self.key_monomial_form)
    }

    // quickly valiate whether a witness is satisfied
    pub fn validate_witness<C: Circuit<E> + Clone>(&self, circuit: C) -> Result<(), SynthesisError> {
        is_satisfied_using_one_shot_check(circuit, &self.hints)
    }

    // generate a plonk proof for a circuit, with witness loaded
    pub fn prove<C: Circuit<E> + Clone>(
        &self,
        circuit: C,
    ) -> Result<Proof<E, PlonkCsWidth4WithNextStepParams>, SynthesisError> {
        is_satisfied_using_one_shot_check(circuit.clone(), &self.hints).expect("must satisfy");
        match &self.key_lagrange_form {
            Some(key_lagrange_form) => {
                prove::<_, _, RollingKeccakTranscript<<E as ScalarEngine>::Fr>>(
                    circuit,
                    &self.hints,
                    &self.setup_polynomials,
                    &self.key_monomial_form,
                    key_lagrange_form,
                )
            },
            None => {
                prove_by_steps::<_, _, RollingKeccakTranscript<<E as ScalarEngine>::Fr>>(
                    circuit,
                    &self.hints,
                    &self.setup_polynomials,
                    None,
                    &self.key_monomial_form,
                    None,
                )
            },
        }
    }

    // calculate the lagrange_form SRS from a monomial_form SRS
    pub fn get_srs_lagrange_form_from_monomial_form(&self) -> Crs<E, CrsForLagrangeForm> {
        Crs::<E, CrsForLagrangeForm>::from_powers(
            &self.key_monomial_form,
            self.setup_polynomials.n.next_power_of_two(),
            &Worker::new(),
        )
    }
}

// verify a plonk proof using a verification key
pub fn verify(
    vk: &VerificationKey<E, PlonkCsWidth4WithNextStepParams>,
    proof: &Proof<E, PlonkCsWidth4WithNextStepParams>
) -> Result<bool, SynthesisError> {
    bellman::plonk::better_cs::verifier::verify::<_, _, RollingKeccakTranscript<<E as ScalarEngine>::Fr>>(proof, vk, None)
}
