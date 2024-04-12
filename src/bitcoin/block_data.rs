use serde::{Deserialize, Serialize};

use crate::bitcoin::BitcoinHeader;
use std::collections::HashMap;
use std::error::Error as ErrorTrait;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use thiserror::Error;

const TEST_DATA_PATH: &str =
    "/Users/hra/Workspace/Code/layerX/bitcoin-fold/src/bitcoin/data/data.json";

#[derive(Error, Debug)]
#[error("transparent")]
pub struct BlockReaderError;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
struct BlockHeaderRpc {
    #[serde(with = "hex")]
    hash: Vec<u8>,
    confirmations: u32,
    height: u32,
    version: u32,
    #[serde(with = "hex")]
    merkleroot: Vec<u8>,
    time: u32,
    nonce: u32,
    #[serde(with = "hex")]
    bits: Vec<u8>,
    #[serde(with = "hex")]
    previousblockhash: Vec<u8>,
}

pub struct BlockReader {
    headers_rpc: HashMap<u32, BlockHeaderRpc>,
}

impl BlockReader {
    pub fn new_from_file(data_file_path: &str) -> Result<BlockReader, Box<dyn ErrorTrait>> {
        let path = Path::new(data_file_path);
        let file = File::open(&path)?;
        let reader = BufReader::new(file);
        let headers: Vec<BlockHeaderRpc> = serde_json::from_reader(reader)?;
        let mut headers_rpc = HashMap::new();
        for header in headers {
            headers_rpc.insert(header.height, header);
        }
        Ok(BlockReader { headers_rpc })
    }

    pub fn new_from_json(json: &str) -> Result<BlockReader, Box<dyn ErrorTrait>> {
        let headers: Vec<BlockHeaderRpc> = serde_json::from_str(json)?;
        let mut headers_rpc = HashMap::new();
        for header in headers {
            headers_rpc.insert(header.height, header);
        }
        Ok(BlockReader { headers_rpc })
    }

    pub fn get_block_header(&self, height: u32) -> Result<BitcoinHeader, Box<dyn ErrorTrait>> {
        if let Some(header) = self.headers_rpc.get(&height) {
            let header = header.clone();
            let mut header_internal = BitcoinHeader {
                version: header.version,
                hash_prev_block: header.previousblockhash,
                hash_merkle_root: header.merkleroot,
                timestamp: header.time,
                target_bits: header.bits,
                nonce: header.nonce,
            };

            // Note: All returned hash values by json-RPC are reversed in reversed order, and need to be transformed back into internal format (reversed) before being used.
            // Ref: https://btcinformation.org/en/glossary/rpc-byte-order
            header_internal.hash_prev_block.reverse();
            header_internal.hash_merkle_root.reverse();

            Ok(header_internal)
        } else {
            Err(Box::new(BlockReaderError))
        }
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;

    #[test]
    fn read_block_headers_in_rpc_format() {
        let reader = BlockReader::new_from_file(TEST_DATA_PATH).unwrap();
        let header_internal = reader.get_block_header(838637).unwrap();
        assert_eq!(header_internal.nonce, 3878033683);
    }
}
