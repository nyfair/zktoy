use std::{
  fs::File,
  io::{BufWriter, Result},
  path::Path,
};
use clap::{Parser, Subcommand};
use bellman::{
  bn256::Bn256,
  kate_commitment::{Crs, CrsForMonomialForm},
  worker::Worker
};
use zktoy::circom_circuit::CircomCircuit;
use zktoy::reader;
use zktoy::plonk;

#[derive(Parser)]
struct Cli {
  #[command(subcommand)]
  command: Commands,
}

#[derive(Subcommand)]
enum Commands {
  /// Generate trusted setup
  Setup {
    /// SRS power_of_two exponent
    #[clap(short, long, default_value="10")]
    power: u8,
    /// Path of generated SRS file
    #[clap(short, long, default_value="zktoy.srs")]
    srs: String
  },
  /// Generate verificationKey key
  Genvk {
    /// Path of SRS file
    #[clap(short, long, default_value="zktoy.srs")]
    srs: String,
    /// Path of given r1cs file
    #[clap(short, long, default_value="test.r1cs")]
    r1cs: String,
    /// Path of generated VK file
    #[clap(short, long, default_value="test.vk")]
    vk: String,
  },
  /// Generate a SNARK proof
  Prove {
    /// Path of SRS file
    #[clap(short, long, default_value="zktoy.srs")]
    srs: String,
    /// Path of given r1cs file
    #[clap(short, long, default_value="test.r1cs")]
    r1cs: String,
    /// Path of witness file
    #[clap(short, long, default_value="test.wtns")]
    witness: String,
    /// Path of generated proof file
    #[clap(short, long, default_value="test.proof")]
    proof: String,
  },
  /// Verify a SNARK proof
  Verify {
    /// Path of proof file
    #[clap(short, long, default_value="test.proof")]
    proof: String,
    /// Path of VK file
    #[clap(short, long, default_value="test.vk")]
    vk: String,
  }
}

fn setup(power: &u8, srs: &String) -> Result<()> {
  let crs = Crs::<Bn256, CrsForMonomialForm>::crs_42(1 << power, &Worker::new());
  let path = Path::new(srs);
  let file = File::create(path)?;
  let writer = BufWriter::new(file);
  crs.write(writer)?;
  Ok(())
}

fn genvk(srs: &String, r1cs: &String, vk: &String) -> Result<()> {
  let circuit = CircomCircuit {
    r1cs: reader::load_r1cs(&r1cs),
    witness: None,
    wire_mapping: None,
    aux_offset: 1,
  };
  let setup = plonk::SetupForProver::prepare_setup_for_prover(
    circuit.clone(),
    reader::load_key_monomial_form(&srs),
    None
  ).expect("fail to initialize");
  let mvk = setup.make_verification_key().expect("fail to generate key");
  let path = Path::new(vk);
  let writer = File::create(path)?;
  mvk.write(writer)?;
  Ok(())
}

fn prove(srs: &String, r1cs: &String, witness: &String, proof: &String) -> Result<()> {
  let circuit = CircomCircuit {
    r1cs: reader::load_r1cs(&r1cs),
    witness: Some(reader::load_witness_from_file::<Bn256>(witness)),
    wire_mapping: None,
    aux_offset: 1,
  };
  let setup = plonk::SetupForProver::prepare_setup_for_prover(
    circuit.clone(),
    reader::load_key_monomial_form(&srs),
    None,
  ).expect("fail to initialize");

  let prover = setup.prove(circuit).unwrap();
  let path = Path::new(proof);
  let writer = File::create(path)?;
  prover.write(writer).unwrap();
  Ok(())
}

fn verify(proof: &String, vk: &String) -> Result<()> {
  let vkey = reader::load_verification_key::<Bn256>(vk);
  let proof = reader::load_proof::<Bn256>(proof);
  match plonk::verify(&vkey, &proof) {
    Ok(true) => {
      println!("Proof is correct");
    },
    Ok(false) => {
      println!("Proof is wrong");
    },
    _ => {
      println!("Invalid proof file");
    }
  }
  Ok(())
}

#[allow(unused_must_use)]
fn main() -> Result<()> {
  let cli = Cli::parse();
  match &cli.command {
    Commands::Setup { power, srs } => {
      setup(power, srs);
    },
    Commands::Genvk { srs, r1cs, vk } => {
      genvk(srs, r1cs, vk);
    },
    Commands::Prove { srs, r1cs, witness, proof } => {
      prove(srs, r1cs, witness, proof);
    },
    Commands::Verify { proof, vk } => {
      verify(proof, vk);
    }
  }
  Ok(())
}