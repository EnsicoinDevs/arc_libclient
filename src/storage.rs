use super::{Data, Outpoint, Point};
use ensicoin_messages::resource::script::OP;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sodiumoxide::crypto::secretbox;
use std::{collections::HashMap, io::prelude::*, sync::Arc};

use super::Wallet;
use futures::Future;
use parking_lot::RwLock;

impl Wallet {
    pub fn open<P>(path: P, key: &[u8]) -> Result<Data, StorageError>
    where
        P: AsRef<std::path::Path>,
    {
        let mut file = std::fs::File::open(path)?;
        let storage: DiskStorage = serde_json::from_reader(&mut file)?;
        let key = secretbox::Key::from_slice(key).ok_or(StorageError::InvalidKey)?;
        let nonce = storage.nonce.clone();
        let storage = WalletStorage::open_storage(storage, &key)?;

        use ripemd160::{Digest, Ripemd160};
        let mut hasher = Ripemd160::new();
        hasher.input(&storage.pub_key.serialize()[..]);
        let pub_key_hash_code = hasher.result().into_iter().map(|b| OP::Byte(b)).collect();

        Ok(Arc::new(RwLock::new(Self {
            nonce,
            owned_tx: storage.decode_txs()?,
            stack: storage.stack,

            pub_key: storage.pub_key,
            secret_key: storage.secret_key,
            pub_key_hash_code,
            signing_engine: Secp256k1::signing_only(),
        })))
    }
    pub fn with_random_key<P>(
        path: P,
        uri: http::Uri,
    ) -> Result<impl futures::Future<Item = (Data, Vec<u8>), Error = super::Error>, super::Error>
    where
        P: AsRef<std::path::Path>,
    {
        let secp = Secp256k1::new();

        let mut rng = rand::thread_rng();
        let (secret_key, pub_key) = secp.generate_keypair(&mut rng);

        let pub_key_hash_code = crate::pub_key_to_op(&pub_key);
        sodiumoxide::init().expect("Crypto creation");

        let (key, nonce) = DiskStorage::create_crypto();
        let wallet = Self {
            nonce: nonce.clone(),
            secret_key,
            pub_key,
            pub_key_hash_code,
            signing_engine: Secp256k1::signing_only(),
            owned_tx: HashMap::new(),
            stack: Vec::new(),
        };
        std::fs::File::create(&path).map_err(StorageError::CreationError)?;
        Ok(wallet.set_genesis(uri)?.and_then(move |wallet| {
            if let Err(e) = wallet.save(path, key.as_ref()) {
                return Err(super::Error::from(e));
            };
            Ok((Arc::new(RwLock::new(wallet)), key.as_ref().to_vec()))
        }))
    }
    pub fn save<P>(&self, path: P, key: &[u8]) -> Result<(), StorageError>
    where
        P: AsRef<std::path::Path>,
    {
        let key = secretbox::Key::from_slice(key).ok_or(StorageError::InvalidKey)?;
        let storage = self.as_storage()?.seal(&key, self.nonce.clone())?;
        let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
        let storage = serde_json::ser::to_string(&storage)?;
        file.write_all(storage.as_bytes())?;
        Ok(())
    }
    pub fn balance(&self) -> u64 {
        self.owned_tx.values().sum()
    }
    fn as_storage(&self) -> Result<WalletStorage, serde_json::Error> {
        let mut owned_serialized = HashMap::new();
        for (utxo, amount) in &self.owned_tx {
            owned_serialized.insert(serde_json::to_string(utxo)?, *amount);
        }
        Ok(WalletStorage {
            secret_key: self.secret_key.clone(),
            pub_key: self.pub_key.clone(),

            owned_tx: owned_serialized,
            stack: self.stack.clone(),
        })
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct WalletStorage {
    owned_tx: HashMap<String, u64>,
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
    fn seal(
        &self,
        key: &secretbox::Key,
        nonce: secretbox::Nonce,
    ) -> Result<DiskStorage, serde_json::Error> {
        let serialized = serde_json::to_string(self)?;
        let cipher = secretbox::seal(serialized.as_bytes(), &nonce, &key);
        Ok(DiskStorage { nonce, cipher })
    }
    fn open_storage(storage: DiskStorage, key: &secretbox::Key) -> Result<Self, StorageError> {
        let storage = secretbox::open(&storage.cipher, &storage.nonce, &key)
            .map_err(|_| StorageError::DecryptError)?;
        let storage = serde_json::from_slice(&storage)?;
        Ok(storage)
    }
    fn decode_txs(&self) -> Result<HashMap<Outpoint, u64>, StorageError> {
        let mut res = HashMap::new();
        for (ser_data, amount) in &self.owned_tx {
            res.insert(serde_json::from_str(ser_data)?, *amount);
        }
        Ok(res)
    }
}

impl DiskStorage {
    fn create_crypto() -> (secretbox::Key, secretbox::Nonce) {
        (secretbox::gen_key(), secretbox::gen_nonce())
    }
}

#[derive(Debug)]
pub enum StorageError {
    IoError(std::io::Error),
    SerDeError(serde_json::Error),
    DecryptError,
    InvalidKey,
    CreationError(std::io::Error),
}

impl From<std::io::Error> for StorageError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err)
    }
}
impl From<serde_json::Error> for StorageError {
    fn from(err: serde_json::Error) -> Self {
        Self::SerDeError(err)
    }
}
