use crypto::PublicKey;
use log::info;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::convert::TryInto;

pub type Index = u32;
pub type Stake = u32;
pub type EpochNumber = u128;

#[derive(Serialize, Deserialize)]
pub struct Parameters {
    pub timeout_delay: u64,
    pub sync_retry_delay: u64,
}

impl Default for Parameters {
    fn default() -> Self {
        Self {
            timeout_delay: 5_000,
            sync_retry_delay: 10_000,
        }
    }
}

impl Parameters {
    pub fn log(&self) {
        // NOTE: These log entries are used to compute performance.
        info!("Timeout delay set to {} rounds", self.timeout_delay);
        info!("Sync retry delay set to {} ms", self.sync_retry_delay);
    }
}

static mut APK: Option<PublicKey> = None;

#[derive(Clone, Serialize, Deserialize)]
pub struct Authority {
    pub index: Index,
    pub stake: Stake,
    pub address: SocketAddr,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Committee {
    pub authorities: HashMap<PublicKey, Authority>,
    pub epoch: EpochNumber,
}

impl Committee {
    pub fn new(info: Vec<(PublicKey, Index, Stake, SocketAddr)>, epoch: EpochNumber) -> Self {
        let c = Self {
            authorities: info
                .into_iter()
                .map(|(name, index, stake, address)| {
                    let authority = Authority { index, stake, address };
                    (name, authority)
                })
                .collect(),
            epoch,
        };
        c.update_apk();
        return c;
    }

    fn update_apk(&self) {
        let pks: Vec<PublicKey> = self.authorities.keys().cloned().collect();
        let pks_with_index: Vec<(PublicKey, u32)> = pks.iter().map(|pk| (*pk, self.get_index(pk))).collect();
        unsafe{
            APK = Some(PublicKey::aggregate_public_keys(&pks_with_index));
        }
    }

    pub fn get_apk(&self) -> PublicKey {
        unsafe{
            if APK == None {
                self.update_apk();
            }
            return APK.unwrap();
        }
    }

    pub fn get_index(&self, pk: &PublicKey) -> u32 {
        let i: u32 = self.authorities.get(pk).unwrap().index.try_into().unwrap();
        return i;
    }

    pub fn size(&self) -> usize {
        self.authorities.len()
    }

    pub fn stake(&self, name: &PublicKey) -> Stake {
        self.authorities.get(name).map_or_else(|| 0, |x| x.stake)
    }

    pub fn quorum_threshold(&self) -> Stake {
        // If N = 3f + 1 + k (0 <= k < 3)
        // then (2 N + 3) / 3 = 2f + 1 + (2k + 2)/3 = 2f + 1 + k = N - f
        let total_votes: Stake = self.authorities.values().map(|x| x.stake).sum();
        2 * total_votes / 3 + 1
    }

    pub fn address(&self, name: &PublicKey) -> Option<SocketAddr> {
        self.authorities.get(name).map(|x| x.address)
    }

    pub fn broadcast_addresses(&self, myself: &PublicKey) -> Vec<(PublicKey, SocketAddr)> {
        self.authorities
            .iter()
            .filter(|(name, _)| name != &myself)
            .map(|(name, x)| (*name, x.address))
            .collect()
    }
}
