use std::env::args;

use TD6::{MESSAGE_SIZE, PUBLIC_KEY_LENGTH};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305,
    aead::{Aead, Payload},
};
use rand::{Rng, thread_rng};
use sha3::{
    Shake128,
    digest::{ExtendableOutput, Update, XofReader, generic_array::GenericArray},
};

fn main() {
    let mut pk: [u8; PUBLIC_KEY_LENGTH] = [0; PUBLIC_KEY_LENGTH];
    hex::decode_to_slice(
        args().nth(1).expect("Please provide the public key"),
        &mut pk,
    )
    .expect("Could not parse public key as a 32-byte hex string");

    let mut rng = thread_rng();
    let mut m = [0u8; MESSAGE_SIZE];
    rng.fill(&mut m);

    let mut g1 = Shake128::default();
    g1.update(&pk);
    let mut pk_hash = [0u8; 128];
    g1.finalize_xof().read(&mut pk_hash);

    let mut g2 = Shake128::default();
    g2.update(&pk_hash);
    g2.update(&m);
    let mut rk = [0u8; 128];
    g2.finalize_xof().read(&mut rk);

    let r = &rk[..rk.len() / 2];
    let k = &rk[rk.len() / 2..];

    let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(&pk));
    let c = cipher
        .encrypt(
            GenericArray::from_slice(r),
            Payload {
                msg: &m,
                aad: &[], // Associated data (if any)
            },
        )
        .expect("Could not encrypt message");

    let mut f = Shake128::default();
    f.update(&c);
    f.update(k);
    let mut k = [0u8; 16];
    f.finalize_xof().read(&mut k);

    println!("{}", hex::encode(c));
    println!("{}", hex::encode(k));
}
