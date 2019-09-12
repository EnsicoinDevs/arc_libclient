use super::{Data, Outpoint, Point};
use ensicoin_messages::resource::script::OP;
use parking_lot::RwLock;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sodiumoxide::crypto::secretbox;
use std::collections::{HashMap, HashSet};
use std::io::prelude::*;
use std::sync::Arc;

pub struct Wallet {
    pub owned_tx: HashMap<Outpoint, u64>,
    pub pub_key: PublicKey,
    secret_key: SecretKey,
    pub_key_hash_code: Vec<OP>,
    stack: Vec<Point>,

    max_height: u64,
    max_block: Vec<u8>,
}

impl Wallet {
    pub(crate) fn pop_stack(&mut self) -> Option<Point> {
        self.stack.pop()
    }
    pub(crate) fn push_stack(&mut self, point: Point) {
        self.stack.push(point)
    }
    pub(crate) fn get_op_hash(&self) -> &[OP] {
        &self.pub_key_hash_code
    }
    pub(crate) fn set_max(&mut self, height: u64, hash: Vec<u8>) {
        self.max_height = height;
        self.max_block = hash;
    }
    fn open<P>(path: P, key: &secretbox::Key) -> Result<Wallet, StorageError>
    where
        P: AsRef<std::path::Path>,
    {
        let mut file = std::fs::File::open(path)?;
        let storage: DiskStorage = ron::de::from_reader(&mut file)?;
        let storage = WalletStorage::open_storage(storage, key)?;

        use ripemd160::{Digest, Ripemd160};
        let mut hasher = Ripemd160::new();
        hasher.input(&storage.pub_key.serialize()[..]);
        let pub_key_hash_code = hasher.result().into_iter().map(|b| OP::Byte(b)).collect();

        Ok(Self {
            owned_tx: storage.owned_tx,
            stack: storage.stack,

            pub_key: storage.pub_key,
            secret_key: storage.secret_key,
            pub_key_hash_code,

            max_block: storage.max_block,
            max_height: storage.max_height,
        })
    }
    pub fn restore<P>(path: P, key: &secretbox::Key, uri: http::Uri) -> Result<Data, StorageError>
    where
        P: AsRef<std::path::Path>,
    {
        let wallet = Wallet::open(path, key)?;
        //TODO
        unimplemented!()
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
            max_block: Vec::new(),
            max_height: 0,
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

            max_height: self.max_height.clone(),
            max_block: self.max_block.clone(),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct WalletStorage {
    owned_tx: HashMap<Outpoint, u64>,
    pub_key: PublicKey,
    secret_key: SecretKey,
    stack: Vec<Point>,

    max_height: u64,
    max_block: Vec<u8>,
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
