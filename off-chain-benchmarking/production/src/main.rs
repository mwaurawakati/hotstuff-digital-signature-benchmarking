extern crate rand7;
extern crate rand8;
extern crate ed25519_dalek;
extern crate bls_signatures;

use rand7::rngs::OsRng;
use ed25519_dalek::Keypair;
use ed25519_dalek::{Signature, Signer};
// use ed25519_dalek::Verifier;

use bls_signatures::*;
use std::time::{Duration, Instant};
use rand8::Rng;


fn main() {
    // eddsa
    let mut csprng = OsRng{};
    let keypair: Keypair = Keypair::generate(&mut csprng);

    let message: &[u8] = b"This is a short message.";
    let mut start = Instant::now();
    let signature: Signature = keypair.sign(message);

    
    assert!(keypair.verify(message, &signature).is_ok());
    let mut duration = start.elapsed();
    println!("Time elapsed in eddsa sign & verify is: {:?}", duration);


    // bls 
    let rng = &mut rand8::thread_rng();

    let private_key = PrivateKey::generate(rng);
    let public_key = vec![private_key.public_key()];
    let msg: Vec<u8> = (0..64).map(|_| rng.gen()).collect();

    start = Instant::now();
    let sig = private_key.sign(&msg);
    let hash = vec![hash(&msg)];
    verify(&sig, &hash, &public_key);
    duration = start.elapsed();
    println!("Time elapsed in bls sign & verify is: {:?}", duration);

}

