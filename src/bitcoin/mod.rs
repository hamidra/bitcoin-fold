pub mod block_data;
mod header;

pub(crate) mod data {
    pub(crate) mod test_json;
}

pub use header::BitcoinHeader;
