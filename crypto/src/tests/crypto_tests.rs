// Copyright(C) Facebook, Inc. and its affiliates.
use super::*;
use ed25519_dalek::Sha512;

impl Hash for &[u8] {
    fn digest(&self) -> Digest {
        Digest(Sha512::digest(self).as_slice()[..32].try_into().unwrap())
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.encode_base64())
    }
}

pub fn keys() -> Vec<(PublicKey, SecretKey)> {
    let rng = &mut rand::thread_rng();
    (0..4).map(|_| generate_keypair(rng)).collect()
}

#[test]
fn import_export_public_key() {
    let (public_key, _) = keys().pop().unwrap();
    let export = public_key.encode_base64();
    let import = PublicKey::decode_base64(&export);
    assert!(import.is_ok());
    assert_eq!(import.unwrap(), public_key);
}

#[test]
fn import_export_secret_key() {
    let (_, secret_key) = keys().pop().unwrap();
    let export = secret_key.encode_base64();
    let import = SecretKey::decode_base64(&export);
    assert!(import.is_ok());
    assert_eq!(import.unwrap(), secret_key);
}

#[test]
fn verify_valid_signature() {
    // Get a keypair.
    let (public_key, secret_key) = keys().pop().unwrap();

    // Make signature.
    let message: &[u8] = b"Hello, world!";
    let digest = message.digest();
    let signature = Signature::new(&digest, &secret_key);

    // Verify the signature.
    assert!(signature.verify(&digest, &public_key).is_ok());
}

#[test]
fn verify_invalid_signature() {
    // Get a keypair.
    let (public_key, secret_key) = keys().pop().unwrap();

    // Make signature.
    let message: &[u8] = b"Hello, world!";
    let digest = message.digest();
    let signature = Signature::new(&digest, &secret_key);

    // Verify the signature.
    let bad_message: &[u8] = b"Bad message!";
    let digest = bad_message.digest();
    assert!(signature.verify(&digest, &public_key).is_err());
}

#[test]
fn verify_valid_batch() {
    // Make signatures.
    let message: &[u8] = b"Hello, world!";
    let digest = message.digest();
    let mut keys = keys();
    let signatures: Vec<_> = (0..3)
        .map(|_| {
            let (public_key, secret_key) = keys.pop().unwrap();
            (public_key, Signature::new(&digest, &secret_key))
        })
        .collect();

    // Verify the batch.
    // println!("{:?}", Signature::verify_batch(&digest, &signatures).is_ok());
    assert!(Signature::verify_batch(&digest, &signatures).is_ok());
}

#[test]
fn verify_invalid_batch() {
    // Make 2 valid signatures.
    let message: &[u8] = b"Hello, world!";
    let digest = message.digest();
    let mut keys = keys();
    let mut signatures: Vec<_> = (0..2)
        .map(|_| {
            let (public_key, secret_key) = keys.pop().unwrap();
            (public_key, Signature::new(&digest, &secret_key))
        })
        .collect();

    // Add an invalid signature.
    let (public_key, _) = keys.pop().unwrap();
    signatures.push((public_key, Signature::default()));

    // Verify the batch.
    assert!(Signature::verify_batch(&digest, &signatures).is_err());
}

#[test]
fn verify_valid_multisig() {
    // Make signatures.
    let message: &[u8] = b"Hello, world!";
    let digest = message.digest();
    let mut keys = keys();
    let signatures: Vec<_> = (0..3)
        .map(|_| {
            let (public_key, secret_key) = keys.pop().unwrap();
            (public_key, Signature::new(&digest, &secret_key))
        })
        .collect();
    
    let (mut public_keys, mut sigs): (Vec<PublicKey>, Vec<Signature>) = signatures.iter().map(|(a,b)| (a.clone(),b.clone())).unzip();
    let asig = Signature::multisig_aggregate(&public_keys, &sigs).unwrap();
    let apk = PublicKey::aggregate_public_keys(&public_keys);

    // Verify the batch.
    assert!(asig.multisig_verify(&public_keys, &digest).is_ok());
    assert!(asig.verify(&digest, &apk).is_ok());

    let apk12 = apk.sub(&public_keys.pop().unwrap());
    sigs.pop();
    let asig12 = Signature::multisig_aggregate(&public_keys, &sigs).unwrap();
    assert!(asig12.verify(&digest, &apk12).is_ok());
}

#[test]
fn verify_invalid_multisig() {
    // Make 2 valid signatures.
    let message: &[u8] = b"Hello, world!";
    let digest = message.digest();
    let mut keys = keys();
    let signatures: Vec<_> = (0..2)
        .map(|_| {
            let (public_key, secret_key) = keys.pop().unwrap();
            (public_key, Signature::new(&digest, &secret_key))
        })
        .collect();

    let (mut public_keys, mut sigs): (Vec<PublicKey>, Vec<Signature>) = signatures.iter().map(|(a,b)| (a.clone(),b.clone())).unzip();

    // Add an invalid signature.
    let (public_key, _) = keys.pop().unwrap();
    public_keys.push(public_key);
    sigs.push(Signature::default());
    let asig = Signature::multisig_aggregate(&public_keys, &sigs).unwrap();

    // Verify the batch.
    assert!(asig.multisig_verify(&public_keys, &digest).is_err());
}

#[test]
fn multisig_aggregate_pks() {
    let pk1 = PublicKey::decode_base64(&"qUWMTJd6KYCvUkkwM4tbaNd5O1/xBoEiJUYK3B5zFZZGC/+U9W8lkJQJAZzoVXyx").unwrap();
    let pk2 = PublicKey::decode_base64(&"iyAaB4DOmqk6JdOIv15FGWZKnHDp/nGowrI2yR3mYcte4J1w3xeaVOLWmE3QIbvI").unwrap();
    let pk3 = PublicKey::decode_base64(&"qRALZZDwJM3dJsiFErD6zRQGoWTRxeFhIJ/PZaZPMI+DQWG3WxR/oOTjVmXhEy5q").unwrap();
    let pk4 = PublicKey::decode_base64(&"sq3cx16Bv8TMQkhgADbz595uAMapjiNEvP6q6iQ98Thrj4t/zjeA0PEIYJLq7njn").unwrap();
    // let sk1 = SecretKey::decode_base64(&"zO/b5BTntAk0/6w/dEAxfGe6PNVG7o/qtHGzSKNLSgg=").unwrap();
    // let sk2 = SecretKey::decode_base64(&"HZjtRPKnV/+eIhpVs5rCRkb5XS12ShMowq5DAdMuyzo=").unwrap();
    // let sk3 = SecretKey::decode_base64(&"rgc3GUSPANeFq9FrG0TnFSACLtC71/afPXnGHfoZn10=").unwrap();
    // let sk4 = SecretKey::decode_base64(&"K/ISv61Jc5h8hWNZXXItDAXMHTXCG8f/N3GmDU2uMSk=").unwrap();
    let pks = vec![pk1,pk2,pk3,pk4];
    // let sks = vec![sk1, sk2, sk3, sk4];

    // let message: &[u8] = b"Hello, world!";
    // let digest = message.digest();
    // let sigs = sks.iter().map(|sk| Signature::new(&digest, &sk)).collect();
    // let asig = Signature::multisig_aggregate(&pks, &sigs).unwrap();

    let apk = PublicKey::aggregate_public_keys(&pks);
    assert!(apk.encode_base64()=="rofYz5Bz1lkvoT6wtmkp+jjFuejiKTT9/te1Z+nG4Jn6ZBRb560QKc7mNHM2f8JV");
}

#[test]
fn test_pk_sub() {
    let pk1 = PublicKey::decode_base64(&"qUWMTJd6KYCvUkkwM4tbaNd5O1/xBoEiJUYK3B5zFZZGC/+U9W8lkJQJAZzoVXyx").unwrap();
    let pk2 = PublicKey::decode_base64(&"iyAaB4DOmqk6JdOIv15FGWZKnHDp/nGowrI2yR3mYcte4J1w3xeaVOLWmE3QIbvI").unwrap();
    let pk3 = PublicKey::decode_base64(&"qRALZZDwJM3dJsiFErD6zRQGoWTRxeFhIJ/PZaZPMI+DQWG3WxR/oOTjVmXhEy5q").unwrap();
    let pk4 = PublicKey::decode_base64(&"sq3cx16Bv8TMQkhgADbz595uAMapjiNEvP6q6iQ98Thrj4t/zjeA0PEIYJLq7njn").unwrap();
    let pks = vec![pk1,pk2,pk3,pk4];

    let apk = PublicKey::aggregate_public_keys(&pks);
    let pk123 = apk.batch_sub(&vec![pk4]);
    let apk123 = PublicKey::aggregate_public_keys(&vec![pk1,pk2,pk3]);
    let apk321 = PublicKey::aggregate_public_keys(&vec![pk3,pk2,pk1]);
    assert!(apk123.encode_base64()==pk123.encode_base64());
    assert!(apk123.encode_base64()==apk321.encode_base64());
}

#[tokio::test]
async fn signature_service() {
    // Get a keypair.
    let (public_key, secret_key) = keys().pop().unwrap();

    // Spawn the signature service.
    let mut service = SignatureService::new(secret_key);

    // Request signature from the service.
    let message: &[u8] = b"Hello, world!";
    let digest = message.digest();
    let signature = service.request_signature(digest.clone()).await;

    // Verify the signature we received.
    assert!(signature.verify(&digest, &public_key).is_ok());
}
