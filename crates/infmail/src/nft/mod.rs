//! NFT-карточки InfMail: генерация (node-canvas + designs.ts), LSB-стеганография, Ed25519.

pub mod card_gen;
pub mod derive;
pub mod lsb;
#[allow(clippy::module_inception)] // GATE: nft::nft is the public designer import path
pub mod nft;
