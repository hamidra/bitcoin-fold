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
        let bytes2: Vec<u8> = header.to_bytes();
        assert_eq!(bytes, [0u8; 80]);
    }

    #[test]
    fn nonzero_version_header_into_bytes() {
        let header = BitcoinHeader {
            version: 10u32,
            hash_prev_block: [0; 32].to_vec(),
            hash_merkle_root: [0; 32].to_vec(),
            timestamp: 0u32,
            target_bits: [0; 4].to_vec(),
            nonce: 0u32,
        };
        let bytes: Vec<u8> = header.to_bytes();
        let mut result = 10u32.to_le_bytes().to_vec();
        result.extend([0u8; 76]);
        assert_eq!(bytes, result);
    }
}
