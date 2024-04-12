use serde::{Deserialize, Serialize};

/// Bitcoin block header
/// Nodes collect new transactions into a block, hash them into a hash tree,
/// and scan through nonce values to make the block's hash satisfy proof-of-work
/// requirements.  When they solve the proof-of-work, they broadcast the block
/// to everyone and the block is added to the block chain.  The first transaction
/// in the block is a special one that creates a new coin owned by the creator
/// of the block.
///
/// ref code: https://github.com/bitcoin/bitcoin/blob/b5d21182e5a66110ce2796c2c99da39c8ebf0d72/src/primitives/block.h#L21
/// ref doc: https://developer.bitcoin.org/reference/block_chain.html

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct BitcoinHeader {
    pub version: u32,
    pub hash_prev_block: Vec<u8>,
    pub hash_merkle_root: Vec<u8>,
    // timestamp
    pub timestamp: u32,
    // target value for the difficulty, which specifies the number of zero bits in the beginning of the target blockhash
    pub target_bits: Vec<u8>,
    // The nonce that was used by the miner to get the block hash with `diffBits` difficulty
    pub nonce: u32,
}

impl BitcoinHeader {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();

        // Convert each field into bytes and append to the result vector
        result.extend_from_slice(&self.version.to_le_bytes());
        result.extend_from_slice(&self.hash_prev_block);
        result.extend_from_slice(&self.hash_merkle_root);
        result.extend_from_slice(&self.timestamp.to_le_bytes());
        result.extend_from_slice(&self.target_bits);
        result.extend_from_slice(&self.nonce.to_le_bytes());

        result
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::BitcoinHeader;
    use crate::bitcoin::block_data::BlockReader;
    use crate::bitcoin::data::test_json::TEST_JSON_RPC;

    #[test]
    fn zero_header_into_bytes() {
        let header = BitcoinHeader {
            version: 0u32,
            hash_prev_block: [0; 32].to_vec(),
            hash_merkle_root: [0; 32].to_vec(),
            timestamp: 0u32,
            target_bits: [0; 4].to_vec(),
            nonce: 0u32,
        };
        let bytes: Vec<u8> = header.to_bytes();
        let expected_bytes: Vec<u8> = [0u8; 80].to_vec();
        assert_eq!(bytes, expected_bytes);
    }

    #[test]
    fn nonzero_version_header_into_bytes() {
        let block_reader = BlockReader::new_from_json(TEST_JSON_RPC).unwrap();

        let header = block_reader.get_block_header(838637).unwrap();
        let bytes: Vec<u8> = header.to_bytes();
        let expected_bytes = hex::decode("00605526382006311de7da73939ef66149fe4217f532f7b821bf0000000000000000000002cc1a24a6dbe5d4b689b04168c61c73ff52aaf34ae1317035e80ad7bb2f2708c4cd1666170362d3131926e7").unwrap();
        assert_eq!(bytes, expected_bytes);
    }
}
