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
// use bls_signatures::aggregate;

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
