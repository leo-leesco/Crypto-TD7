use std::{
    env::args,
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305,
    aead::{Aead, Payload},
};
use sha3::{
    Shake128,
    digest::{ExtendableOutput, Update, XofReader, generic_array::GenericArray},
};

fn main() {
    let mut args = args();

    let sk_file = File::open(Path::new(
        &args
            .nth(1)
            .expect("Please provide the path to the secret key file"),
    ))
    .expect("Could not open secret key file");
    let lines: Vec<String> = BufReader::new(sk_file)
        .lines()
        .collect::<Result<_, _>>()
        .expect("Could not collect lines from secret key file");
    assert_eq!(
        lines.len(),
        4,
        "The secret key file should have 4 lines (SK,S,PK,PKH)"
    );
    let sk = hex::decode(lines.first().unwrap())
        .expect("Could not read first line as a hex encoded secret key");
    let s = hex::decode(lines.get(1).unwrap())
        .expect("Could not read first line as a hex encoded nonce");
    let pk = hex::decode(lines.get(1).unwrap())
        .expect("Could not read first line as a hex encoded public key");
    let pk_hash = hex::decode(lines.get(1).unwrap())
        .expect("Could not read first line as a hex encoded public key hash");

    let c = hex::decode(args.nth(2).expect("Please provide the ciphertext"))
        .expect("Could not parse ciphertext as a hex string");

    let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(&sk));
    let m = cipher
        .decrypt(
            GenericArray::from_slice(&s),
            Payload {
                msg: &c,
                aad: &[], // Associated data (if any)
            },
        )
        .expect("Could not decrypt message");

    let mut g2 = Shake128::default();
    g2.update(&pk_hash);
    g2.update(&m);
    let mut rk = [0u8; 128];
    g2.finalize_xof().read(&mut rk);

    let r = &rk[..rk.len() / 2];
    let k = &rk[rk.len() / 2..];

    let mut f = Shake128::default();
    f.update(&c);
    f.update(k);
    let mut k0 = [0u8; 16];
    f.finalize_xof().read(&mut k0);

    let mut f = Shake128::default();
    f.update(&c);
    f.update(&s);
    let mut k1 = [0u8; 16];
    f.finalize_xof().read(&mut k1);

    let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(&pk));
    let k = if c
        == cipher
            .encrypt(
                GenericArray::from_slice(r),
                Payload {
                    msg: &m,
                    aad: &[], // Associated data (if any)
                },
            )
            .expect("Could not encrypt message")
    {
        k0
    } else {
        k1
    };
    println!("{}", hex::encode(k));
}
