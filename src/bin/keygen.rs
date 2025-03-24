use clap::Parser;
use TD7::frodo::Frodo;

use std::fs::File;
use std::io::Write;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Public key file path
    #[arg(short, long)]
    publickey_file_path: String,

    /// Secret key file path
    #[arg(short, long)]
    secretkey_file_path: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Initialize Frodo parameters
    let frodo = Frodo::default();

    // Generate keys
    let (public_key, secret_key) = frodo.keygen();

    // Save public key
    let mut pk_file = File::create(&args.publickey_file_path)?;
    pk_file.write_all(&public_key.serialize())?;
    println!("Public key written to {}", args.publickey_file_path);

    // Save secret key
    let mut sk_file = File::create(&args.secretkey_file_path)?;
    sk_file.write_all(&secret_key.serialize())?;
    println!("Secret key written to {}", args.secretkey_file_path);

    Ok(())
}
