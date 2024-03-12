use ark_bls12_381::Config;
use ark_ec::bls12::{G2Affine, G2Projective};
use ark_ec::models::short_weierstrass::Projective;
use ark_ec::{AffineRepr, CurveGroup};
use ark_std::Zero;
use bls12_381::Scalar;
use core::ops::{Add, Sub};
use rand_core::{CryptoRng, RngCore};
use serde::{de, ser, Deserialize, Serialize};
use sha2::Digest as sha2_digest;
use sha2::Sha256;
use std::array::TryFromSliceError;
use std::convert::{TryFrom, TryInto};
use std::fmt;
use tokio::sync::mpsc::{channel, Sender};
use tokio::sync::oneshot;
use w3f_bls::single::SignedMessage;
use w3f_bls::SerializableToBytes;
use w3f_bls::Signed;
use w3f_bls::{
    engine::UsualBLS, DoublePublicKey, DoubleSignature, Message, PublicKey as W3fPublicKey,
    SecretKey as W3fSecretKey, Signature as W3fSignature,
};

#[cfg(test)]
#[path = "tests/crypto_tests.rs"]
pub mod crypto_tests;
pub type TinyBLSG2 = UsualBLS<ark_bls12_381::Bls12_381, ark_bls12_381::Config>;
pub type CryptoError = bls_signatures::Error;

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
        write!(
            f,
            "{}",
            base64::encode(&self.0)
                .get(0..16)
                .expect("failed to encode base 64")
        )
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

#[derive(Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct PublicKey(pub [u8; 48]);

impl PublicKey {
    /// Encodes the public key as a base64 string.
    pub fn encode_base64(&self) -> String {
        base64::encode(&self.0[..])
    }

    /// Decodes a public key from a base64 string.
    pub fn decode_base64(s: &str) -> Result<Self, base64::DecodeError> {
        let bytes = base64::decode(s)?;
        let array: [u8; 48] = bytes
            .try_into()
            .map_err(|_| base64::DecodeError::InvalidLength)?;
        Ok(Self(array))
    }

    /// Aggregates multiple public keys into a single public key.
    pub fn aggregate_public_keys(public_keys: &Vec<PublicKey>) -> Self {
        let mut aggregated_pk = Projective::zero();
        for i in 0..public_keys.len() {
            let point = W3fPublicKey::<TinyBLSG2>::from_bytes(&public_keys[i].0)
                .expect("failed to get public key")
                .0
                .into_affine();
            aggregated_pk = aggregated_pk.add(point);
        }
        let gr = aggregated_pk.into_affine().into_group();
        let apk = PublicKey(
            W3fPublicKey::<TinyBLSG2>(gr).to_bytes()[..]
                .try_into()
                .expect("Unexpected public key length"),
        );
        return apk;
    }

    pub fn hash_to_scalar(&self) -> Scalar {
        let mut hasher = Sha256::new();
        hasher.update(&self.encode_base64());
        let hash: [u8; 32] = hasher.finalize()[..]
            .try_into()
            .expect("failed to finalize harsher");
        // convert the hash to little endian
        let mut le_hash = [0u8; 32];
        for i in 0..hash.len() - 4 {
            if i % 4 == 0 {
                le_hash[i] = hash[i + 3];
            }
            if i % 4 == 1 {
                le_hash[i] = hash[i + 1];
            }
            if i % 4 == 2 {
                le_hash[i] = hash[i - 1];
            }
            if i % 4 == 3 {
                le_hash[i] = hash[i - 3];
            }
        }
        Scalar::from_bytes(&le_hash).unwrap()
    }

    pub fn sub(&self, other_pk: &PublicKey) -> Self {
        let this_pk = W3fPublicKey::<TinyBLSG2>::from_bytes(self.0.as_ref())
            .expect("failed to create public key")
            .0;
        let other_pk_p = W3fPublicKey::<TinyBLSG2>::from_bytes(other_pk.0.as_ref())
            .expect("failed to create public key")
            .0;
        let result = this_pk.sub(other_pk_p.clone());
        return PublicKey(
            W3fPublicKey::<TinyBLSG2>(result).to_bytes()[..]
                .try_into()
                .expect("Unexpected public key length"),
        );
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
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.encode_base64())
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.encode_base64())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::decode_base64(&s).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}",
            self.encode_base64().get(0..16).expect("failed to encode")
        )
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
    let secret_key = W3fSecretKey::<TinyBLSG2>::generate(rng);
    let secret_key_bytes = secret_key.to_bytes();
    let public_key_bytes = secret_key.into_public().to_bytes();
    let secret = SecretKey(
        secret_key_bytes[..32]
            .try_into()
            .expect("Unexpected secret length"),
    );
    let public = PublicKey(
        public_key_bytes[..48]
            .try_into()
            .expect("Unexpected public length"),
    );
    (public, secret)
}
// Represents a signature.
/// Represents an ed25519 signature.
#[derive(Clone, Debug)]
pub struct Signature {
    part1: [u8; 48],
    part2: [u8; 48],
}

impl Signature {
    pub fn new(digest: &Digest, secret: &SecretKey) -> Self {
        let mut private_key = W3fSecretKey::<TinyBLSG2>::from_bytes(&secret.0)
            .expect("failed to create public key from bytes");
        let mes = Message(digest.0, digest.0.to_vec());
        let sig = private_key.sign_once(&mes).to_bytes();
        let part1 = sig[..48].try_into().expect("Unexpected signature length");
        let part2 = sig[48..96].try_into().expect("Unexpected signature length");
        Signature { part1, part2 }
    }

    pub fn flatten(&self) -> [u8; 96] {
        [self.part1, self.part2]
            .concat()
            .try_into()
            .expect("Unexpected signature length")
    }

    pub fn from_bytes(part1: [u8; 48], part2: [u8; 48]) -> Self {
        Signature { part1, part2 }
    }

    pub fn verify(&self, digest: &Digest, public_key: &PublicKey) -> Result<(), CryptoError> {
        let sig = match W3fSignature::from_bytes(&self.flatten()) {
            Ok(sig) => sig,
            Err(_) => return Err(bls_signatures::Error::GroupDecode),
        };

        let public_key = match W3fPublicKey::<TinyBLSG2>::from_bytes(&public_key.0) {
            Ok(pk) => pk,
            Err(_) => return Err(bls_signatures::Error::GroupDecode),
        };

        let mes = Message(digest.0, digest.0.to_vec());

        let signed_message = SignedMessage {
            message: mes,
            publickey: public_key,
            signature: sig,
        };

        if signed_message.verify() {
            Ok(())
        } else {
            Err(bls_signatures::Error::GroupDecode)
        }
    }

    pub fn verify_batch<'a, I>(digest: &Digest, votes: I) -> Result<(), CryptoError>
    where
        I: IntoIterator<Item = &'a (PublicKey, Signature)>,
    {
        let msg = Message(digest.0, digest.0.to_vec());

        let results: Result<Vec<()>, CryptoError> = votes
            .into_iter()
            .map(|(key, sig)| {
                let signature = W3fSignature::from_bytes(&sig.flatten())
                    .map_err(|_| bls_signatures::Error::GroupDecode)?;

                let pub_key = W3fPublicKey::<TinyBLSG2>::from_bytes(&key.0)
                    .map_err(|_| bls_signatures::Error::GroupDecode)?;

                let signed_message = SignedMessage {
                    message: msg.clone(),
                    publickey: pub_key,
                    signature: signature,
                };
                if signed_message.verify() {
                    Ok(())
                } else {
                    Err(bls_signatures::Error::GroupDecode)
                }
            })
            .collect();
        results.map(|_| ())
    }

    pub fn verify_aggregated_signature(
        &self,
        digests: &Vec<Digest>,
        public_keys: &Vec<PublicKey>,
    ) -> Result<(), CryptoError> {
        let messages: Vec<Message> = digests
            .into_iter()
            .map(|digest| Message(digest.0, digest.0.to_vec()))
            .collect();
        let pub_keys: Vec<_> = public_keys
            .into_iter()
            .map(|public_key| {
                W3fPublicKey::<TinyBLSG2>::from_bytes(&public_key.0)
                    .expect("failed to create public key from bytes")
            })
            .collect();
        let sig = W3fSignature::from_bytes(&self.flatten())
            .expect("failed to create public key from bytes");
        let mut agr = w3f_bls::multi_pop_aggregator::MultiMessageSignatureAggregatorAssumingPoP::<
            TinyBLSG2,
        >::new();
        // TODO: Check if vec lens are equal
        for (msg, pk) in messages.iter().zip(pub_keys.iter()) {
            agr.add_message_n_publickey(msg, pk);
        }
        agr.add_signature(&sig);
        if agr.verify() {
            return Ok(());
        } else {
            return Err(bls_signatures::Error::GroupDecode);
        }
    }

    pub fn aggregate_signatures(signatures: &Vec<Signature>) -> Self {
        let sigs: Vec<_> = signatures
            .into_iter()
            .map(|signature| {
                W3fSignature::from_bytes(&signature.flatten())
                    .expect("failed to create signature from bytes")
            })
            .collect();
        let mut agr = w3f_bls::multi_pop_aggregator::MultiMessageSignatureAggregatorAssumingPoP::<
            TinyBLSG2,
        >::new();
        for sig in sigs.into_iter() {
            agr.add_signature(&sig);
        }
        let agrr = &agr;
        let sig = agrr.signature().to_bytes();
        let part1 = sig[..48].try_into().expect("Unexpected signature length");
        let part2 = sig[48..96].try_into().expect("Unexpected signature length");
        Signature { part1, part2 }
    }

    pub fn multisig_aggregate(
        public_keys: &Vec<PublicKey>,
        signatures: &Vec<Signature>,
    ) -> Result<Self, CryptoError> {
        if public_keys.len() != signatures.len() {
            return Err(bls_signatures::Error::SizeMismatch);
        }
        if signatures.len() == 0 {
            return Err(bls_signatures::Error::ZeroSizedInput);
        }
        let mut aggregated_sig = Projective::zero();
        for i in 0..signatures.len() {
            let g2point =
                W3fSignature::<TinyBLSG2>::from_bytes(&signatures[i].flatten().as_slice())
                    .expect("failed to create G2 affine")
                    .0
                    .into_affine();
            aggregated_sig = aggregated_sig.add(g2point);
        }
        let sig = W3fSignature::<TinyBLSG2>(aggregated_sig.into_affine().into_group()).to_bytes();
        let part1 = sig[..48].try_into().expect("Unexpected signature length");
        let part2 = sig[48..96].try_into().expect("Unexpected signature length");
        return Ok(Signature { part1, part2 });
    }

    pub fn multisig_verify(
        &self,
        public_keys: &Vec<PublicKey>,
        digest: &Digest,
    ) -> Result<(), CryptoError> {
        if public_keys.len() == 0 {
            return Err(bls_signatures::Error::ZeroSizedInput);
        }
        let apk = PublicKey::aggregate_public_keys(public_keys);
        return self.verify(digest, &apk);
    }

    pub fn encode_base64(&self) -> String {
        base64::encode(&self.flatten())
    }

    pub fn decode_base64(s: &str) -> Result<Self, base64::DecodeError> {
        let bytes = base64::decode(s)?;
        let part1 = bytes[..48]
            .try_into()
            .map_err(|_| base64::DecodeError::InvalidLength)?;
        let part2 = bytes[48..96]
            .try_into()
            .map_err(|_| base64::DecodeError::InvalidLength)?;
        Ok(Self {
            part1: part1,
            part2: part2,
        })
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
        let part_one: [u8; 48] = [
            162, 232, 231, 10, 66, 26, 80, 44, 248, 229, 168, 94, 63, 157, 110, 50, 124, 171, 134,
            165, 183, 122, 42, 133, 192, 223, 88, 80, 96, 242, 127, 15, 82, 106, 91, 229, 103, 242,
            122, 173, 51, 129, 249, 42, 151, 211, 196, 205,
        ];
        let part_two: [u8; 48] = [
            7, 42, 35, 183, 33, 205, 246, 184, 216, 200, 128, 174, 31, 24, 37, 63, 14, 80, 182, 71,
            247, 165, 139, 173, 165, 75, 104, 117, 124, 27, 234, 105, 70, 118, 0, 217, 180, 7, 208,
            40, 20, 60, 208, 195, 148, 15, 48, 201,
        ];
        Self {
            part1: part_one,
            part2: part_two,
        }
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
