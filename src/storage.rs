use super::{Data, Outpoint, Point};
use ensicoin_messages::resource::script::OP;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sodiumoxide::crypto::secretbox;
use std::{collections::HashMap, io::prelude::*, sync::Arc};

use super::Wallet;
use parking_lot::RwLock;

impl Wallet {
    pub fn open<P>(path: P, key: &[u8]) -> Result<Data, StorageError>
    where
        P: AsRef<std::path::Path>,
    {
        let mut file = std::fs::File::open(path)?;
        let storage: DiskStorage = ron::de::from_reader(&mut file)?;
        let key = secretbox::Key::from_slice(key).ok_or(StorageError::InvalidKey)?;
        let storage = WalletStorage::open_storage(storage, &key)?;

        use ripemd160::{Digest, Ripemd160};
        let mut hasher = Ripemd160::new();
        hasher.input(&storage.pub_key.serialize()[..]);
        let pub_key_hash_code = hasher.result().into_iter().map(|b| OP::Byte(b)).collect();

        Ok(Arc::new(RwLock::new(Self {
            owned_tx: storage.owned_tx,
            stack: storage.stack,

            pub_key: storage.pub_key,
            secret_key: storage.secret_key,
            pub_key_hash_code,
        })))
    }
    pub fn with_random_key<P>(path: P) -> Result<(Data, secretbox::Key), StorageError>
    where
        P: AsRef<std::path::Path>,
    {
        let secp = Secp256k1::new();

        let mut rng = rand::thread_rng();
        let (secret_key, pub_key) = secp.generate_keypair(&mut rng);

        use ripemd160::{Digest, Ripemd160};
        let mut hasher = Ripemd160::new();
        hasher.input(&pub_key.serialize()[..]);
        let pub_key_hash_code = hasher.result().into_iter().map(|b| OP::Byte(b)).collect();
        // TODO: Not forget on load
        sodiumoxide::init().expect("Crypto creation");

        let wallet = Self {
            secret_key,
            pub_key,
            pub_key_hash_code,
            owned_tx: HashMap::new(),
            stack: Vec::new(),
        };
        let (storage, key) = wallet.as_storage().create_disk_storage()?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        let storage = ron::ser::to_string(&storage)?;
        file.write_all(storage.as_bytes())?;
        Ok((Arc::new(RwLock::new(wallet)), key))
    }
    pub fn balance(&self) -> u64 {
        self.owned_tx.values().sum()
    }
    fn as_storage(&self) -> WalletStorage {
        WalletStorage {
            secret_key: self.secret_key.clone(),
            pub_key: self.pub_key.clone(),

            owned_tx: self.owned_tx.clone(),
            stack: self.stack.clone(),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct WalletStorage {
    owned_tx: HashMap<Outpoint, u64>,
    pub_key: PublicKey,
    secret_key: SecretKey,
    stack: Vec<Point>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct DiskStorage {
    nonce: secretbox::Nonce,
    #[serde(deserialize_with = "from_base64", serialize_with = "as_base64")]
    cipher: Vec<u8>,
}

fn as_base64<T, S>(key: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: AsRef<[u8]>,
    S: serde::Serializer,
{
    serializer.serialize_str(&base64::encode(key.as_ref()))
}

fn from_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as DeError;
    <String as serde::Deserialize>::deserialize(deserializer)
        .and_then(|string| base64::decode(&string).map_err(|err| DeError::custom(err.to_string())))
}

impl WalletStorage {
    fn create_disk_storage(&self) -> Result<(DiskStorage, secretbox::Key), ron::ser::Error> {
        let key = secretbox::gen_key();
        let nonce = secretbox::gen_nonce();
        let serialized = ron::ser::to_string(self)?;
        let cipher = secretbox::seal(serialized.as_bytes(), &nonce, &key);
        Ok((DiskStorage { nonce, cipher }, key))
    }
    fn open_storage(storage: DiskStorage, key: &secretbox::Key) -> Result<Self, StorageError> {
        let storage = secretbox::open(&storage.cipher, &storage.nonce, &key)
            .map_err(|_| StorageError::DecryptError)?;
        let storage = ron::de::from_bytes(&storage)?;
        Ok(storage)
    }
}

#[derive(Debug)]
pub enum StorageError {
    IoError(std::io::Error),
    SerError(ron::ser::Error),
    DeError(ron::de::Error),
    DecryptError,
    InvalidKey,
}

impl From<std::io::Error> for StorageError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err)
    }
}
impl From<ron::ser::Error> for StorageError {
    fn from(err: ron::ser::Error) -> Self {
        Self::SerError(err)
    }
}
impl From<ron::de::Error> for StorageError {
    fn from(err: ron::de::Error) -> Self {
        Self::DeError(err)
    }
}
