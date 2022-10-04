// Copyright(C) Facebook, Inc. and its affiliates.
use serde::{de, ser, Deserialize, Serialize};
use std::array::TryFromSliceError;
use std::convert::{TryFrom, TryInto};
use std::fmt;
use tokio::sync::mpsc::{channel, Sender};
use tokio::sync::oneshot;
use rand_core::{CryptoRng, RngCore};
use bls_signatures::Serialize as bls_Serialize;
use bls_signatures::PrivateKey as bls_PrivateKey;
use bls_signatures::Signature as bls_Signature;
use bls_signatures::PublicKey as bls_PublicKey;
use bls_signatures::aggregate as bls_aggregate;
use bls_signatures::verify as bls_verify;
use bls_signatures::hash as bls_hash;
use bls_signatures::Error;
use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use sha2::Digest as sha2_digest;
use sha2::Sha256;

#[cfg(test)]
#[path = "tests/crypto_tests.rs"]
pub mod crypto_tests;

pub type CryptoError = Error;

/// Represents a hash digest (32 bytes).
#[derive(Hash, PartialEq, Default, Eq, Clone, Deserialize, Serialize, Ord, PartialOrd)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn size(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", base64::encode(&self.0))
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", base64::encode(&self.0).get(0..16).unwrap())
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Digest {
    type Error = TryFromSliceError;
    fn try_from(item: &[u8]) -> Result<Self, Self::Error> {
        Ok(Digest(item.try_into()?))
    }
}

/// This trait is implemented by all messages that can be hashed.
pub trait Hash {
    fn digest(&self) -> Digest;
}

/// Represents a public key (in bytes).
#[derive(Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct PublicKey(pub [u8; 48]);

impl PublicKey {
    pub fn encode_base64(&self) -> String {
        base64::encode(&self.0[..])
    }

    pub fn decode_base64(s: &str) -> Result<Self, base64::DecodeError> {
        let bytes = base64::decode(s)?;
        let array = bytes[..48]
            .try_into()
            .map_err(|_| base64::DecodeError::InvalidLength)?;
        Ok(Self(array))
    }

    pub fn hash_to_scalar(&self) -> Scalar {
        let mut hasher = Sha256::new();
        hasher.update(&self.encode_base64());
        let hash: [u8; 32] = hasher.finalize()[..].try_into().unwrap();
        // convert the hash to little endian
        let mut le_hash = [0u8; 32];
        for i in 0..hash.len()-4{
            if i % 4 == 0{
                le_hash[i] = hash[i+3];
            }
            if i % 4 == 1{
                le_hash[i] = hash[i+1];
            }
            if i % 4 == 2{
                le_hash[i] = hash[i-1];
            }
            if i % 4 == 3{
                le_hash[i] = hash[i-3];
            }
        }
        return Scalar::from_bytes(&le_hash).unwrap();
    }

    pub fn aggregate_public_keys(public_keys: &Vec<PublicKey>) -> Self {
        let mut t = Vec::new();
        for pk in public_keys {
            t.push(pk.hash_to_scalar());
        }
        let mut aggregated_pk = G1Projective::identity();
        for i in 0..t.len(){
            let g1point = G1Affine::from_compressed(&public_keys[i].0).unwrap();
            aggregated_pk += g1point * t[i];
        }
        let apk = PublicKey(bls_PublicKey::from(aggregated_pk).as_bytes()[..].try_into().expect("Unexpected public key length"));
        return apk;
    }

    pub fn sub(&self, other_pk: &PublicKey) -> Self {
        let this_pk = G1Affine::from_compressed(&self.0).unwrap();
        let result: G1Projective = G1Projective::from(&this_pk) - (G1Affine::from_compressed(&other_pk.0).unwrap() * other_pk.hash_to_scalar());
        return PublicKey(bls_PublicKey::from(result).as_bytes()[..].try_into().expect("Unexpected public key length"));
    }

    pub fn batch_sub(&self, other_pks: &Vec<PublicKey>) -> Self {
        let mut apk = PublicKey(self.0);
        for pk in other_pks.iter() {
            apk = apk.sub(pk);
        }
        return apk;
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.encode_base64())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.encode_base64().get(0..16).unwrap())
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&self.encode_base64())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let value = Self::decode_base64(&s).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Default for PublicKey {
    fn default() -> Self {
        let default: u8 = 0;
        Self([default; 48])
    }
}

/// Represents a secret key (in bytes).
pub struct SecretKey([u8; 32]);

impl SecretKey {
    pub fn encode_base64(&self) -> String {
        base64::encode(&self.0[..])
    }

    pub fn decode_base64(s: &str) -> Result<Self, base64::DecodeError> {
        let bytes = base64::decode(s)?;
        let array = bytes[..32]
            .try_into()
            .map_err(|_| base64::DecodeError::InvalidLength)?;
        Ok(Self(array))
    }
}

impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&self.encode_base64())
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let value = Self::decode_base64(&s).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(|x| *x = 0);
    }
}

pub fn generate_production_keypair() -> (PublicKey, SecretKey) {
    let rng = &mut rand::thread_rng();
    generate_keypair(rng)
}

pub fn generate_keypair<R>(rng: &mut R) -> (PublicKey, SecretKey)
where
    R: RngCore + CryptoRng,
{
    let private_key = bls_PrivateKey::generate(rng);
    let private_bytes = private_key.as_bytes();
    let public_bytes = private_key.public_key().as_bytes();
    let secret = SecretKey(private_bytes[..32].try_into().expect("Unexpected secret length"));
    let public = PublicKey(public_bytes[..48].try_into().expect("Unexpected public length"));
    (public, secret)
}

/// Represents an ed25519 signature.
#[derive(Clone, Debug)]
pub struct Signature {
    part1: [u8; 48],
    part2: [u8; 48],
}

impl Signature {
    pub fn new(digest: &Digest, secret: &SecretKey) -> Self {
        let private_key = bls_PrivateKey::from_bytes(&secret.0).unwrap();
        let sig = private_key.sign(&digest.0).as_bytes();
        let part1 = sig[..48].try_into().expect("Unexpected signature length");
        let part2 = sig[48..96].try_into().expect("Unexpected signature length");
        Signature { part1, part2 }
    }

    pub fn flatten(&self) -> [u8; 96] {
        [self.part1, self.part2].concat().try_into().expect("Unexpected signature length")
    }

    pub fn from_bytes(part1: [u8; 48], part2: [u8; 48]) -> Self {
        Signature { part1, part2 }
    }
    

    pub fn verify(&self, digest: &Digest, public_key: &PublicKey) -> Result<(), CryptoError> {
        let sig = bls_Signature::from_bytes(&self.flatten()).unwrap();
        let public_key = vec![bls_PublicKey::from_bytes(&public_key.0).unwrap()];
        let messages = vec![bls_hash(&digest.0)];
        if bls_verify(&sig, &messages[..], &public_key){
            return Ok(());
        }
        else{
            return Err(Error::GroupDecode);
        }
    }

    pub fn verify_batch<'a, I>(digest: &Digest, votes: I) -> Result<(), CryptoError>
    where
        I: IntoIterator<Item = &'a (PublicKey, Signature)>,
    {
        let msg = vec![bls_hash(&digest.0)];
        for (key, sig) in votes.into_iter() {
            let signature = bls_Signature::from_bytes(&sig.flatten()).unwrap();
            let pub_key = vec![bls_PublicKey::from_bytes(&key.0).unwrap()];
            if bls_verify(&signature, &msg[..], &pub_key) == false {
                return Err(Error::GroupDecode);
            }
        }
        return Ok(());
    }

    pub fn verify_aggregated_signature(&self, digests: &Vec<Digest>, public_keys: &Vec<PublicKey>) -> Result<(), CryptoError> {
        let messages: Vec<_> = digests.into_iter().map(|digest| bls_hash(&digest.0)).collect();
        let pub_keys: Vec<_> = public_keys.into_iter().map(|public_key| bls_PublicKey::from_bytes(&public_key.0).unwrap()).collect();
        let sig = bls_Signature::from_bytes(&self.flatten()).unwrap();
        if bls_verify(&sig, &messages[..], &pub_keys[..]){
            return Ok(());
        }
        else{
            return Err(Error::GroupDecode);
        }
    }

    pub fn aggregate_signatures(signatures: &Vec<Signature>) -> Self {
        let sigs: Vec<_> = signatures.into_iter().map(|signature| bls_Signature::from_bytes(&signature.flatten()).unwrap()).collect();
        let sig = bls_aggregate(&sigs[..]).unwrap().as_bytes();
        let part1 = sig[..48].try_into().expect("Unexpected signature length");
        let part2 = sig[48..96].try_into().expect("Unexpected signature length");
        Signature { part1, part2 }
    }

    pub fn multisig_aggregate(public_keys: &Vec<PublicKey>, signatures: &Vec<Signature>) -> Result<Self, CryptoError> {
        if public_keys.len() != signatures.len() {
            return Err(Error::SizeMismatch);
        }
        if signatures.len() == 0 {
            return Err(Error::ZeroSizedInput);
        }
        let mut t = Vec::new();
        for pk in public_keys {
            t.push(pk.hash_to_scalar());
        }
        
        let mut aggregated_sig = G2Projective::identity();
        for i in 0..t.len(){
            let g2point = G2Affine::from_compressed(&signatures[i].flatten()).unwrap();
            aggregated_sig += g2point * t[i];
        }
        let sig = bls_Signature::from(aggregated_sig).as_bytes();
        let part1 = sig[..48].try_into().expect("Unexpected signature length");
        let part2 = sig[48..96].try_into().expect("Unexpected signature length");
        return Ok(Signature { part1, part2 })
    }

    pub fn multisig_verify(&self, public_keys: &Vec<PublicKey>, digest: &Digest) -> Result<(), CryptoError> {
        if public_keys.len() == 0 {
            return Err(Error::ZeroSizedInput)
        }
        let apk = PublicKey::aggregate_public_keys(public_keys);
        return self.verify(digest, &apk)
    }

    pub fn encode_base64(&self) -> String {
        base64::encode(&self.flatten())
    }

    pub fn decode_base64(s: &str) -> Result<Self, base64::DecodeError> {
        let bytes = base64::decode(s)?;
        let part1 = bytes[..48].try_into().map_err(|_| base64::DecodeError::InvalidLength)?;
        let part2 = bytes[48..96].try_into().map_err(|_| base64::DecodeError::InvalidLength)?;
        Ok(Self { part1: part1, part2: part2 })
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&self.encode_base64())
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let value = Self::decode_base64(&s).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl Default for Signature {
    fn default() -> Self {
        // A random signature
        let part_one: [u8; 48] = [162, 232, 231, 10, 66, 26, 80, 44, 248, 229, 168, 94, 63, 157, 110, 50, 124, 171, 134, 165, 183, 122, 42, 133, 192, 223, 88, 80, 96, 242, 127, 15, 82, 106, 91, 229, 103, 242, 122, 173, 51, 129, 249, 42, 151, 211, 196, 205];
        let part_two: [u8; 48] = [7, 42, 35, 183, 33, 205, 246, 184, 216, 200, 128, 174, 31, 24, 37, 63, 14, 80, 182, 71, 247, 165, 139, 173, 165, 75, 104, 117, 124, 27, 234, 105, 70, 118, 0, 217, 180, 7, 208, 40, 20, 60, 208, 195, 148, 15, 48, 201];
        Self { part1: part_one, part2: part_two }
    }
}

/// This service holds the node's private key. It takes digests as input and returns a signature
/// over the digest (through a oneshot channel).
#[derive(Clone)]
pub struct SignatureService {
    channel: Sender<(Digest, oneshot::Sender<Signature>)>,
}

impl SignatureService {
    pub fn new(secret: SecretKey) -> Self {
        let (tx, mut rx): (Sender<(_, oneshot::Sender<_>)>, _) = channel(100);
        tokio::spawn(async move {
            while let Some((digest, sender)) = rx.recv().await {
                let signature = Signature::new(&digest, &secret);
                let _ = sender.send(signature);
            }
        });
        Self { channel: tx }
    }

    pub async fn request_signature(&mut self, digest: Digest) -> Signature {
        let (sender, receiver): (oneshot::Sender<_>, oneshot::Receiver<_>) = oneshot::channel();
        if let Err(e) = self.channel.send((digest, sender)).await {
            panic!("Failed to send message Signature Service: {}", e);
        }
        receiver
            .await
            .expect("Failed to receive signature from Signature Service")
    }
}



// ------------ EdDSA --------------



use ed25519_dalek as dalek;
use ed25519_dalek::ed25519;
use ed25519_dalek::Signer as _;
use rand7::rngs::OsRng as OsRng7;
use rand7::CryptoRng as CryptoRng7;
use rand7::RngCore as RngCore7;
use ed25519_dalek::ed25519::Error as EdDSAError;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Default)]
pub struct EdDSAPublicKey(pub [u8; 32]);

impl EdDSAPublicKey {
    pub fn encode_base64(&self) -> String {
        base64::encode(&self.0[..])
    }

    pub fn decode_base64(s: &str) -> Result<Self, base64::DecodeError> {
        let bytes = base64::decode(s)?;
        let array = bytes[..32]
            .try_into()
            .map_err(|_| base64::DecodeError::InvalidLength)?;
        Ok(Self(array))
    }
}

impl fmt::Debug for EdDSAPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.encode_base64())
    }
}

impl fmt::Display for EdDSAPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.encode_base64().get(0..16).unwrap())
    }
}

impl Serialize for EdDSAPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&self.encode_base64())
    }
}

impl<'de> Deserialize<'de> for EdDSAPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let value = Self::decode_base64(&s).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl AsRef<[u8]> for EdDSAPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub struct EdDSASecretKey([u8; 64]);

impl EdDSASecretKey {
    pub fn encode_base64(&self) -> String {
        base64::encode(&self.0[..])
    }

    pub fn decode_base64(s: &str) -> Result<Self, base64::DecodeError> {
        let bytes = base64::decode(s)?;
        let array = bytes[..64]
            .try_into()
            .map_err(|_| base64::DecodeError::InvalidLength)?;
        Ok(Self(array))
    }
}

impl Serialize for EdDSASecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&self.encode_base64())
    }
}

impl<'de> Deserialize<'de> for EdDSASecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let value = Self::decode_base64(&s).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl Drop for EdDSASecretKey {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(|x| *x = 0);
    }
}

pub fn generate_EdDSA_production_keypair() -> (EdDSAPublicKey, EdDSASecretKey) {
    generate_EdDSA_keypair(&mut OsRng7)
}

pub fn generate_EdDSA_keypair<R>(csprng: &mut R) -> (EdDSAPublicKey, EdDSASecretKey)
where
    R: CryptoRng7 + RngCore7,
{
    let keypair = dalek::Keypair::generate(csprng);
    let public = EdDSAPublicKey(keypair.public.to_bytes());
    let secret = EdDSASecretKey(keypair.to_bytes());
    (public, secret)
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct EdDSASignature {
    part1: [u8; 32],
    part2: [u8; 32],
}

impl EdDSASignature {
    pub fn new(digest: &Digest, secret: &EdDSASecretKey) -> Self {
        let keypair = dalek::Keypair::from_bytes(&secret.0).expect("Unable to load secret key");
        let sig = keypair.sign(&digest.0).to_bytes();
        let part1 = sig[..32].try_into().expect("Unexpected signature length");
        let part2 = sig[32..64].try_into().expect("Unexpected signature length");
        EdDSASignature { part1, part2 }
    }

    pub fn from_bytes(part1: [u8; 32], part2: [u8; 32]) -> Self {
        EdDSASignature { part1, part2 }
    }

    pub fn flatten(&self) -> [u8; 64] {
        [self.part1, self.part2]
            .concat()
            .try_into()
            .expect("Unexpected signature length")
    }

    pub fn verify(&self, digest: &Digest, public_key: &EdDSAPublicKey) -> Result<(), EdDSAError> {
        let signature = ed25519::signature::Signature::from_bytes(&self.flatten())?;
        let key = dalek::PublicKey::from_bytes(&public_key.0)?;
        key.verify_strict(&digest.0, &signature)
    }

    pub fn verify_batch<'a, I>(digest: &Digest, votes: I) -> Result<(), EdDSAError>
    where
        I: IntoIterator<Item = &'a (EdDSAPublicKey, EdDSASignature)>,
    {
        let mut messages: Vec<&[u8]> = Vec::new();
        let mut signatures: Vec<dalek::Signature> = Vec::new();
        let mut keys: Vec<dalek::PublicKey> = Vec::new();
        for (key, sig) in votes.into_iter() {
            messages.push(&digest.0[..]);
            signatures.push(ed25519::signature::Signature::from_bytes(&sig.flatten())?);
            keys.push(dalek::PublicKey::from_bytes(&key.0)?);
        }
        dalek::verify_batch(&messages[..], &signatures[..], &keys[..])
    }
}