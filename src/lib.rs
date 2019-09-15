use futures::{Future, Stream};
use hyper::client::connect::{Destination, HttpConnector};
use parking_lot::RwLock;
use std::sync::Arc;
use tower_grpc::Request;
use tower_hyper::{client, util};
use tower_util::MakeService;

mod storage;
mod wallet;
pub use wallet::Wallet;

#[macro_use]
extern crate log;

pub mod node {
    include!(concat!(env!("OUT_DIR"), "/ensicoin_rpc.rs"));
}

use node::{Block, GetBestBlocksRequest, GetBlockByHashRequest, PublishRawTxRequest, Tx};

#[derive(Debug)]
pub enum Error {
    GrpcError(tower_grpc::Status),
    TransportError(hyper::Error),
    ConnectError(tower_hyper::client::ConnectError<std::io::Error>),
    ChannelError,
    Storage(storage::StorageError),
}

impl From<storage::StorageError> for Error {
    fn from(err: storage::StorageError) -> Self {
        Self::Storage(err)
    }
}

impl From<tokio::sync::mpsc::error::SendError> for Error {
    fn from(_: tokio::sync::mpsc::error::SendError) -> Self {
        Self::ChannelError
    }
}

impl From<hyper::Error> for Error {
    fn from(err: hyper::Error) -> Self {
        Self::TransportError(err)
    }
}

impl From<tower_hyper::client::ConnectError<std::io::Error>> for Error {
    fn from(err: tower_hyper::client::ConnectError<std::io::Error>) -> Self {
        Self::ConnectError(err)
    }
}

impl From<tower_grpc::Status> for Error {
    fn from(err: tower_grpc::Status) -> Self {
        Self::GrpcError(err)
    }
}

#[derive(Debug, Hash, PartialEq, Eq, Clone, serde::Serialize, serde::Deserialize)]
pub struct Outpoint {
    pub hash: Vec<u8>,
    pub index: u32,
}

impl From<node::Outpoint> for Outpoint {
    fn from(value: node::Outpoint) -> Self {
        Self {
            hash: value.hash,
            index: value.index,
        }
    }
}

#[derive(Debug, Hash, PartialEq, Eq, Copy, Clone, serde::Serialize, serde::Deserialize)]
pub enum EffectKind {
    Spend,
    Credit,
}

#[derive(Debug, Hash, PartialEq, Eq, Clone, serde::Serialize, serde::Deserialize)]
pub struct Effect {
    pub amount: u64,
    pub target: Outpoint,
    pub kind: EffectKind,
}


#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct Point {
    pub height: u32,
    pub hash: Vec<u8>,
    pub previous_hash: Vec<u8>,
    pub effects: Vec<Effect>,
}

type Data = Arc<RwLock<Wallet>>;

pub fn for_balance_udpate<F, U>(
    uri: http::Uri,
    wallet: Data,
    update: F,
) -> impl Future<Item = (), Error = Error>
where
    F: FnMut(u64) -> U,
    U: futures::IntoFuture<Item = (), Error = Error>,
{
    futures_new::compat::Compat::new(Box::pin(balance_updater(uri, wallet)))
        .and_then(|stream| stream.for_each(update))
}

async fn balance_updater(
    uri: http::Uri,
    wallet: Data,
) -> Result<impl Stream<Item = u64, Error = Error>, Error> {
    let stream = following_txs(uri.clone(), wallet.clone()).await?;
    let return_stream = stream.map(move |point| {
        {
            let mut wallet_guard = wallet.write();
            while point.height < wallet_guard.height() as u32 {
                wallet_guard.pop();
            }
        }
        (wallet.clone(), point)
    }).and_then(move |(wallet, point)| futures_new::compat::Compat::new(Box::pin(fork_wallet(uri.clone(), wallet, point))));
    Ok(return_stream)
}

async fn fork_wallet(uri: http::Uri, wallet: Data, point: Point) -> Result<u64, Error> {
    let balance = wallet.read().balance();
    Ok(balance)
}

async fn following_txs(
    uri: http::Uri,
    wallet: Data,
) -> Result<impl Stream<Item = Point, Error = Error>, Error> {
    let dst = Destination::try_from_uri(uri.clone())?;
    let connector = util::Connector::new(HttpConnector::new(4));
    let settings = client::Builder::new().http2_only(true).clone();
    let mut make_client = client::Connect::with_builder(connector, settings);
    let (stream, mut client) = futures_new::compat::Compat01As03::new(
        make_client
            .make_service(dst)
            .map_err(Error::from)
            .and_then(move |conn| {
                use node::client::Node;
                let conn = tower_request_modifier::Builder::new()
                    .set_origin(uri)
                    .build(conn)
                    .unwrap();

                Node::new(conn).ready().map_err(Error::from)
            })
            .and_then(|mut client| {
                client
                    .get_best_blocks(Request::new(GetBestBlocksRequest {}))
                    .map_err(Error::from)
                    .map(move |response| (response, client))
            }),
    )
    .await?;
    let response_stream = stream
        .into_inner()
        .map_err(Error::from)
        .and_then(move |response| {
            client
                .get_block_by_hash(Request::new(GetBlockByHashRequest {
                    hash: response.hash,
                }))
                .map_err(Error::from)
        })
        .map(|reply| reply.into_inner())
        .map(move |reply| match reply.block {
            Some(block) => Point {
                height: block.height as u32,
                hash: block.hash,
                previous_hash: block.prev_block,
                effects: wallet.write().affects(block.txs),
            },
            None => Point {
                height: 0,
                effects: Vec::new(),
                hash: Vec::new(),
                previous_hash: Vec::new(),
            },
        });
    Ok(response_stream)
}
