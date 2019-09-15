use super::{Effect, EffectKind, Outpoint, Point};
use ensicoin_messages::resource::script::{Script, OP};
use ensicoin_serializer::{Deserialize, Deserializer};
use secp256k1::{PublicKey, SecretKey};
use std::collections::HashMap;

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
}

impl Wallet {
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
        if !self.stack.is_empty() {
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
        (self.stack.is_empty() && height == 0)
            || (!self.stack.is_empty()
                && (self.stack.len() + 1 == height as usize
                    && self.stack.last().unwrap().hash == prev_hash))
    }
    #[inline]
    pub fn is_next_block(&self, block: &super::Block) -> bool {
        self.is_next_point(block.height, &block.prev_block)
    }
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.stack.is_empty()
    }
    #[inline]
    pub fn last_known(&self) -> Option<(usize, &[u8])> {
        self.stack
            .last()
            .map(|p| (self.stack.len(), p.hash.as_ref()))
    }
    #[inline]
    pub fn height(&self) -> usize {
        self.stack.len()
    }
}
