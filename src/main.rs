use std::io::Write;
use std::num::NonZeroU32;

use anyhow::anyhow;
use argon2::Argon2;
use clap::Parser;
use rpassword::prompt_password;
use thiserror::Error;
use zeroize::Zeroizing;

const PROMPT: &str = "mnemonic: ";

#[derive(Debug, Error)]
#[error("{inner}")]
struct Error {
    inner: argon2::Error,
}

struct EncodeState {
    has_alpha_lower: bool,
    has_alpha_upper: bool,
    has_digit: bool,
    has_special_char: bool,
}

/// Password generator based on mnemonics
#[derive(Clone, Parser, Debug)]
#[command(version, about, long_about = None)]
struct Arguments {
    /// Number of threads to use
    #[arg(long, default_value = "1")]
    threads: NonZeroU32,
    /// Number of kdf iterations
    #[arg(long, default_value = "3")]
    iterations: NonZeroU32,
    /// Mnemonic to feed into the kdf
    ///
    /// This argument is optional. Ideally, we should
    /// read it from stdin
    #[arg(short, long)]
    mnemonic: Option<Zeroizing<String>>,
    /// Data to salt the password with
    ///
    /// The value should be unique per generated
    /// password
    ///
    /// Typically, website hostnames should be chosen as a salt
    #[arg(short, long)]
    salt: String,
    /// Monotonically increasing counter
    ///
    /// This value should be kept safe
    ///
    /// It can be used to reset passwords, by incrementing its value
    #[arg(long, default_value_t = Box::new(0))]
    counter: Box<u32>,
    /// Length in bytes of the kdf output
    #[arg(long, default_value_t = 32)]
    hash_length: usize,
}

fn main() -> anyhow::Result<()> {
    let args = Arguments::parse();
    let mut counter = args.counter;

    let params = argon2::Params::new(
        argon2::Params::DEFAULT_M_COST,
        args.iterations.get(),
        args.threads.get(),
        Some(args.hash_length),
    )
    .map_err(Error::wrap)?;

    let mnemonic = {
        args.mnemonic
            .map_or_else(|| prompt_password(PROMPT).map(Zeroizing::new), Ok)?
    };
    let output_pass = generate_pass(&mnemonic, &args.salt, &counter, params)?;
    {
        // scuffed zeroizing of the counter
        unsafe {
            std::ptr::write_volatile(&mut *counter as *mut _, 0u32);
        }
        drop(counter);
    }

    println!("{}", output_pass.as_str());
    Ok(())
}

impl Error {
    fn wrap(inner: argon2::Error) -> Self {
        Self { inner }
    }
}

fn generate_pass(
    mnemonic: &str,
    salt: &str,
    counter: &u32,
    params: argon2::Params,
) -> anyhow::Result<Zeroizing<String>> {
    let mut nonce = 0u32;
    let hash_length = params.output_len().unwrap();

    let mnemonic = {
        let mut out = format!("{counter:08x}");
        out.push_str(mnemonic);
        Zeroizing::new(out)
    };

    loop {
        let mut state = EncodeState {
            has_alpha_lower: false,
            has_alpha_upper: false,
            has_digit: false,
            has_special_char: false,
        };

        let salt = {
            let mut out = format!("{nonce:08x}");
            out.push_str(salt);
            out
        };
        let mut output_key_material = Zeroizing::new(vec![0u8; hash_length]);
        Argon2::new(
            argon2::Algorithm::default(),
            argon2::Version::default(),
            params.clone(),
        )
        .hash_password_into(
            mnemonic.as_bytes(),
            salt.as_bytes(),
            &mut output_key_material,
        )
        .map_err(Error::wrap)?;

        let mut output = Zeroizing::new(String::with_capacity(output_key_material.len()));

        for ch in output_key_material.iter().copied() {
            match () {
                _ if ch.is_ascii_punctuation() => {
                    output.push(ch as char);
                    state.has_special_char = true;
                }
                _ if ch.is_ascii_digit() => {
                    output.push(ch as char);
                    state.has_digit = true;
                }
                _ if ch.is_ascii_lowercase() => {
                    output.push(ch as char);
                    state.has_alpha_lower = true;
                }
                _ if ch.is_ascii_uppercase() => {
                    output.push(ch as char);
                    state.has_alpha_upper = true;
                }
                _ => {
                    let mut buf = [0u8; 2];
                    if state.has_alpha_lower {
                        _ = writeln!(&mut buf[..], "{ch:02X}");
                    } else {
                        _ = writeln!(&mut buf[..], "{ch:02x}");
                    }
                    for buf_ch in buf {
                        match () {
                            _ if buf_ch.is_ascii_digit() => {
                                state.has_digit = true;
                            }
                            _ if buf_ch.is_ascii_lowercase() => {
                                state.has_alpha_lower = true;
                            }
                            _ if buf_ch.is_ascii_uppercase() => {
                                state.has_alpha_upper = true;
                            }
                            _ => unreachable!(),
                        }
                        output.push(buf_ch as char);
                    }
                }
            }
        }

        if state.complete() {
            break Ok(output);
        }

        nonce = nonce
            .checked_add(1)
            .ok_or_else(|| anyhow!("nonce overflow"))?;
    }
}

impl EncodeState {
    #[inline]
    const fn complete(&self) -> bool {
        self.has_alpha_lower && self.has_alpha_upper && self.has_digit && self.has_special_char
    }
}
