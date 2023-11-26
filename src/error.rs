use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("kdf error: {0}")]
    Argon2(argon2::Error),
    #[error("mnemonic mismatch")]
    MnemonicMismatch,
    #[error("io error: {0}")]
    Io(io::Error),
}
