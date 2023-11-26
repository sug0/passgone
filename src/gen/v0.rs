use std::io::Write;

use anyhow::anyhow;
use argon2::Argon2;
use zeroize::Zeroizing;

use crate::error::Error;

struct EncodeState {
    has_alpha_lower: bool,
    has_alpha_upper: bool,
    has_digit: bool,
    has_special_char: bool,
}

impl EncodeState {
    #[inline]
    const fn complete(&self) -> bool {
        self.has_alpha_lower && self.has_alpha_upper && self.has_digit && self.has_special_char
    }
}

pub fn generate_pass(
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
        .map_err(Error::Argon2)?;

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
