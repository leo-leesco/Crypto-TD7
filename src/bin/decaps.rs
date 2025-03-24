use clap::Parser;
use std::fs::File;
use std::io::{Read, Write};
use TD7::frodo::{Ciphertext, Frodo, SecretKey};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Private key file path
    #[arg(short, long)]
    privatekey_file_path: String,

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

    // Read secret key
    let mut sk_data = Vec::new();
    let mut sk_file = File::open(&args.privatekey_file_path)?;
    sk_file.read_to_end(&mut sk_data)?;
    let secret_key = SecretKey::deserialize(&sk_data)?;

    // Read ciphertext
    let mut ct_data = Vec::new();
    let mut ct_file = File::open(&args.ciphertext_file_path)?;
    ct_file.read_to_end(&mut ct_data)?;
    let ciphertext = Ciphertext::deserialize(&ct_data)?;

    // Decapsulate
    let shared_secret = frodo.decaps(&secret_key, &ciphertext);

    // Save shared secret
    let mut ss_file = File::create(&args.sharedsecretkey_file_path)?;
    ss_file.write_all(&shared_secret)?;
    println!(
        "Shared secret written to {}",
        args.sharedsecretkey_file_path
    );

    Ok(())
}
