use super::{node, Effect, EffectKind, Outpoint, Point};
use ensicoin_messages::resource::script::{Script, OP};
use ensicoin_serializer::{Deserialize, Deserializer};
use secp256k1::{PublicKey, SecretKey};
use std::collections::HashMap;

use futures::Future;
use hyper::client::connect::{Destination, HttpConnector};
use tower_grpc::Request;
use tower_hyper::{client, util};
use tower_util::MakeService;

#[derive(Debug)]
pub enum PushError {
    PreviousBlockIsNotTop,
}

pub struct Wallet {
    pub(crate) owned_tx: HashMap<Outpoint, u64>,

    pub pub_key: PublicKey,
    pub(crate) secret_key: SecretKey,
    pub(crate) pub_key_hash_code: Vec<OP>,

    pub(crate) stack: Vec<Point>,

    pub(crate) nonce: sodiumoxide::crypto::secretbox::Nonce,
}

impl Wallet {
    pub(crate) fn set_genesis(
        mut self,
        uri: http::Uri,
    ) -> Result<impl Future<Item = Self, Error = super::Error>, super::Error> {
        let dst = Destination::try_from_uri(uri.clone())?;
        let connector = util::Connector::new(HttpConnector::new(4));
        let settings = client::Builder::new().http2_only(true).clone();
        let mut make_client = client::Connect::with_builder(connector, settings);

        Ok(make_client
            .make_service(dst)
            .map_err(super::Error::from)
            .and_then(move |conn| {
                use node::client::Node;
                let conn = tower_request_modifier::Builder::new()
                    .set_origin(uri)
                    .build(conn)
                    .unwrap();

                Node::new(conn).ready().map_err(super::Error::from)
            })
            .and_then(|mut client| {
                client
                    .get_info(Request::new(node::GetInfoRequest {}))
                    .map_err(super::Error::from)
                    .and_then(move |response| {
                        if self.stack.len() != 0 {
                            panic!("Cannot init non empty wallet")
                        };
                        self.stack = vec![Point {
                            hash: response.into_inner().genesis_block_hash,
                            effects: Vec::new(),
                            height: 0,
                            previous_hash: Vec::new(),
                        }];
                        Ok(self)
                    })
            }))
    }

    pub fn affects(&self, txs: Vec<super::Tx>) -> Vec<Effect> {
        let mut affect = Vec::new();
        let mut script = vec![OP::Dup, OP::Hash160, OP::Push(20)];
        script.extend_from_slice(&self.pub_key_hash_code);
        script.append(&mut vec![OP::Equal, OP::Verify, OP::Checksig]);
        let script = ensicoin_messages::resource::script::Script::from(script);
        for tx in txs {
            let hash = tx.hash;
            for input in tx.inputs {
                if let Some(outpoint) = input.previous_output {
                    let utxo = Outpoint::from(outpoint);
                    if let Some(value) = self.owned_tx.get(&utxo) {
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

    fn do_effect(&mut self, effect: Effect) {
        match effect.kind {
            EffectKind::Credit => {
                self.owned_tx.insert(effect.target, effect.amount);
            }
            EffectKind::Spend => {
                self.owned_tx.remove(&effect.target);
            }
        }
    }
    fn undo_effect(&mut self, effect: Effect) {
        match effect.kind {
            EffectKind::Credit => {
                self.owned_tx.remove(&effect.target);
            }
            EffectKind::Spend => {
                self.owned_tx.insert(effect.target, effect.amount);
            }
        }
    }

    pub fn pop(&mut self) {
        if self.stack.len() > 1 {
            for effect in self.stack.pop().unwrap().effects {
                self.undo_effect(effect);
            }
        }
    }
    pub(crate) fn push_point(&mut self, point: Point) -> Result<(), PushError> {
        if self.is_next_point(point.height, &point.previous_hash) {
            for effect in point.effects.clone() {
                self.do_effect(effect);
            }
            self.stack.push(point);
            Ok(())
        } else {
            Err(PushError::PreviousBlockIsNotTop)
        }
    }
    fn is_next_point(&self, height: u32, prev_hash: &[u8]) -> bool {
        self.stack.len() == height as usize && self.stack.last().unwrap().hash == prev_hash
    }
    #[inline]
    pub fn is_next_block(&self, block: &super::node::BlockHeader) -> bool {
        self.is_next_point(block.height, &block.prev_block)
    }
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.stack.is_empty()
    }
    #[inline]
    pub fn height(&self) -> usize {
        self.stack.len()
    }
    #[inline]
    pub fn top_hash(&self) -> Option<&[u8]> {
        self.stack.last().map(|p| p.hash.as_ref())
    }
}
