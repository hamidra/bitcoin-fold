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

    static TEST_JSON_RPC: &str = r#"[
        {
          "hash": "0000000000000000000219957045483495e40610b47cd600152ec76e256ba523",
          "confirmations": 4,
          "height": 838637,
          "version": 643129344,
          "versionHex": "26556000",
          "merkleroot": "08272fbbd70ae8357031e14af3aa52ff731cc66841b089b6d4e5dba6241acc02",
          "time": 1712770500,
          "mediantime": 1712769033,
          "nonce": 3878033683,
          "bits": "170362d3",
          "difficulty": 83126997340024.61,
          "chainwork": "00000000000000000000000000000000000000007399bba0f3fa18aa519f5160",
          "nTx": 3734,
          "previousblockhash": "00000000000000000000bf21b8f732f51742fe4961f69e9373dae71d31062038",
          "nextblockhash": "0000000000000000000033626df1e30e05522c90643dbf33113d684465d53fc6"
        },
        {
          "hash": "0000000000000000000033626df1e30e05522c90643dbf33113d684465d53fc6",
          "confirmations": 3,
          "height": 838638,
          "version": 813080576,
          "versionHex": "3076a000",
          "merkleroot": "d91c9095632f82e55a7e34fd955dbfbef0d5275393815afc76b3f4ac7bec7aeb",
          "time": 1712770854,
          "mediantime": 1712769105,
          "nonce": 4255188596,
          "bits": "170362d3",
          "difficulty": 83126997340024.61,
          "chainwork": "0000000000000000000000000000000000000000739a073bc2bab6e38bceec80",
          "nTx": 3394,
          "previousblockhash": "0000000000000000000219957045483495e40610b47cd600152ec76e256ba523",
          "nextblockhash": "000000000000000000034c4c2caedc73b08bd64a6ffe4ae3f5852f9369a15a9d"
        }
      ]"#;

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
