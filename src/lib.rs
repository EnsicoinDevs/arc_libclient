use futures::{Future, Stream};
use hyper::client::connect::{Destination, HttpConnector};
use tower_grpc::Request;
use tower_hyper::{client, util};
use tower_util::MakeService;
use std::sync::Arc;

use std::collections::HashSet;

pub mod node {
    include!(concat!(env!("OUT_DIR"), "/ensicoin_rpc.rs"));
}

use node::{Block, GetBestBlocksRequest, GetBlockByHashRequest, PublishRawTxRequest, Tx};

type PubKey = [u8; 33];

pub struct BalanceUpdate {
    pub tx: Tx,
    pub amount: i64,
    pub block: Vec<u8>,
}

#[derive(Debug)]
pub enum Error {
    GrpcError(tower_grpc::Status),
    TransportError(hyper::Error),
    ConnectError(tower_hyper::client::ConnectError<std::io::Error>),
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

fn has_debiting_tx(response: &Block, wallet: Data) -> bool {
    for tx in &response.txs {
        for input in &tx.inputs {
            if let Some(outpoint) = &input.previous_output {
                if wallet.owned_tx.contains(&outpoint.hash) {
                    return true;
                }
            }
        }
    }
    return false;
}

pub struct Wallet {
    pub owned_tx: HashSet<Vec<u8>>,
}

type Data = Arc<Wallet>;

pub async fn following_txs(uri: http::Uri, wallet: Data) -> Result<impl Stream< Item = Block, Error = Error>, Error> {
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
        }).map(|reply| reply.into_inner())
        .filter(move |reply| match &reply.block {
            Some(block) => has_debiting_tx(&block, wallet.clone()),
            None => false,
        }).map(|reply| reply.block.unwrap());
    Ok(response_stream)
}
