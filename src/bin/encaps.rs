use clap::Parser;
use std::fs::File;
use std::io::{Read, Write};
use TD7::frodo::{Frodo, PublicKey};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Public key file path
    #[arg(short, long)]
    publickey_file_path: String,

    /// Ciphertext file path
    #[arg(short, long)]
    ciphertext_file_path: String,

    /// Shared secret key file path
    #[arg(short, long)]
    sharedsecretkey_file_path: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Initialize Frodo parameters
    let frodo = Frodo::default();

    // Read public key
    let mut pk_data = Vec::new();
    let mut pk_file = File::open(&args.publickey_file_path)?;
    pk_file.read_to_end(&mut pk_data)?;
    let public_key = PublicKey::deserialize(&pk_data)?;

    // Encapsulate
    let (ciphertext, shared_secret) = frodo.encaps(&public_key);

    // Save ciphertext
    let mut ct_file = File::create(&args.ciphertext_file_path)?;
    ct_file.write_all(&ciphertext.serialize())?;
    println!("Ciphertext written to {}", args.ciphertext_file_path);

    // Save shared secret
    let mut ss_file = File::create(&args.sharedsecretkey_file_path)?;
    ss_file.write_all(&shared_secret)?;
    println!(
        "Shared secret written to {}",
        args.sharedsecretkey_file_path
    );

    Ok(())
}
