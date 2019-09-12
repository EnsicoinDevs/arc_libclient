use futures::{Future, Stream};
use hyper::client::connect::{Destination, HttpConnector};
use parking_lot::RwLock;
use std::sync::Arc;
use tower_grpc::Request;
use tower_hyper::{client, util};
use tower_util::MakeService;

use ensicoin_messages::resource::script::{OP, Script};
use ensicoin_serializer::{Deserialize, Deserializer, Serialize};
mod storage;
pub use storage::Wallet;

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

fn affecting_tx(response: Vec<Tx>, wallet: Data) -> Vec<Effect> {
    let wallet = wallet.read();
    let mut affect = Vec::new();
    let mut script = vec![OP::Dup, OP::Hash160, OP::Push(20)];
    script.extend_from_slice(&wallet.get_op_hash());
    script.append(&mut vec![OP::Equal, OP::Verify, OP::Checksig]);
    let script = Script::from(script);
    for tx in response {
        let hash = tx.hash;
        for input in tx.inputs {
            if let Some(outpoint) = input.previous_output {
                let utxo = Outpoint::from(outpoint);
                if let Some(value) = wallet.owned_tx.get(&utxo) {
                    affect.push(Effect {
                        kind: EffectKind::Spend,
                        target: utxo,
                        amount: *value,
                    });
                }
            }
        }
        for (output_index, output) in tx.outputs.into_iter().enumerate() {
            let value = output.value;
            let mut de = Deserializer::new(bytes::BytesMut::from(output.script));
            match Script::deserialize(&mut de) {
                Ok(v) => {
                    if v == script {
                        affect.push(Effect {
                            kind: EffectKind::Credit,
                            target: Outpoint {
                                hash: hash.clone(),
                                index: output_index as u32,
                            },
                            amount: value,
                        });
                    }
                }
                Err(e) => warn!("Invalid script in tx: {:?}", e),
            };
        }
    }
    affect
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct Point {
    pub height: u64,
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
    let stream = following_txs(uri, wallet.clone()).await?;
    let return_stream = stream.map(move |point| {
        let mut wallet = wallet.write();
        let last_valid = loop {
            match wallet.pop_stack() {
                Some(stack_point) => {
                    if stack_point.hash == point.previous_hash {
                        break Some(stack_point);
                    } else {
                        for Effect {
                            amount,
                            target,
                            kind,
                        } in stack_point.effects
                        {
                            match kind {
                                EffectKind::Credit => {
                                    wallet.owned_tx.remove(&target);
                                }
                                EffectKind::Spend => {
                                    wallet.owned_tx.insert(target, amount);
                                }
                            }
                        }
                    }
                }
                None => break None,
            }
        };
        if let Some(last_valid) = last_valid {
            wallet.push_stack(last_valid)
        }
        for effect in &point.effects {
            match effect.kind {
                EffectKind::Credit => {
                    wallet.owned_tx.insert(effect.target.clone(), effect.amount);
                }
                EffectKind::Spend => {
                    wallet.owned_tx.remove(&effect.target);
                }
            }
        }
        wallet.set_max(point.height, point.hash.clone());
        wallet.push_stack(point);
        wallet.balance()
    });
    Ok(return_stream)
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
                height: block.height as u64,
                hash: block.hash,
                previous_hash: block.prev_block,
                effects: affecting_tx(block.txs, wallet.clone()),
            },
            None => Point {
                height: 0,
                effects: Vec::new(),
                hash: Vec::new(),
                previous_hash: Vec::new(),
            },
        })
        .filter(|p| !p.effects.is_empty());
    Ok(response_stream)
}
