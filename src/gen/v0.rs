use std::io::Write;

use anyhow::anyhow;
use argon2::Argon2;
use zeroize::Zeroizing;

use crate::entropy;
use crate::error::Error;

#[inline]
pub fn generate_pass_with_repeats(
    min_entropy: Option<f64>,
    mnemonic: &str,
    salt: &str,
    counter: &u32,
    truncate: Option<usize>,
    params: argon2::Params,
) -> anyhow::Result<Zeroizing<String>> {
    generate_pass::<true>(min_entropy, mnemonic, salt, counter, truncate, params)
}

#[inline]
pub fn generate_pass_without_repeats(
    min_entropy: Option<f64>,
    mnemonic: &str,
    salt: &str,
    counter: &u32,
    truncate: Option<usize>,
    params: argon2::Params,
) -> anyhow::Result<Zeroizing<String>> {
    generate_pass::<false>(min_entropy, mnemonic, salt, counter, truncate, params)
}

struct EncodeState {
    has_repeated_ch: bool,
    has_alpha_lower: bool,
    has_alpha_upper: bool,
    has_digit: bool,
    has_special_char: bool,
}

impl EncodeState {
    #[inline]
    const fn complete<const ALLOW_REPEATS: bool>(&self) -> bool {
        (ALLOW_REPEATS || !self.has_repeated_ch)
            && self.has_alpha_lower
            && self.has_alpha_upper
            && self.has_digit
            && self.has_special_char
    }
}

fn handle_repeats<const ALLOW_REPEATS: bool>(
    ch: u8,
    last_ch: &mut Option<u8>,
    state: &mut EncodeState,
) {
    if !ALLOW_REPEATS && Some(ch) == *last_ch {
        state.has_repeated_ch = true;
    }
    *last_ch = Some(ch);
}

fn generate_pass<const ALLOW_REPEATS: bool>(
    min_entropy: Option<f64>,
    mnemonic: &str,
    salt: &str,
    counter: &u32,
    truncate: Option<usize>,
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
            has_repeated_ch: false,
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
        let mut last_ch = None;

        for ch in output_key_material.iter().copied() {
            match () {
                _ if ch.is_ascii_punctuation() => {
                    handle_repeats::<ALLOW_REPEATS>(ch, &mut last_ch, &mut state);
                    output.push(ch as char);
                    state.has_special_char = true;
                }
                _ if ch.is_ascii_digit() => {
                    handle_repeats::<ALLOW_REPEATS>(ch, &mut last_ch, &mut state);
                    output.push(ch as char);
                    state.has_digit = true;
                }
                _ if ch.is_ascii_lowercase() => {
                    handle_repeats::<ALLOW_REPEATS>(ch, &mut last_ch, &mut state);
                    output.push(ch as char);
                    state.has_alpha_lower = true;
                }
                _ if ch.is_ascii_uppercase() => {
                    handle_repeats::<ALLOW_REPEATS>(ch, &mut last_ch, &mut state);
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
                        handle_repeats::<ALLOW_REPEATS>(buf_ch, &mut last_ch, &mut state);
                        output.push(buf_ch as char);
                    }
                }
            }
        }

        if state.complete::<ALLOW_REPEATS>()
            && min_entropy
                .map(|ent| entropy::shannon(&output) > ent)
                .unwrap_or(true)
        {
            if let Some(new_len) = truncate {
                output.truncate(new_len);
            }

            break Ok(output);
        }

        nonce = nonce
            .checked_add(1)
            .ok_or_else(|| anyhow!("nonce overflow"))?;
    }
}

#[cfg(all(test, feature = "test-vectors"))]
mod test_vectors {
    //! Version 0 test vectors. Run with `cargo test --release --features test-vectors`.

    use super::*;

    #[test]
    fn run() -> anyhow::Result<()> {
        assert_eq!(
            &*generate_pass_with_repeats(
                None,
                "bong",
                "bing",
                &0u32,
                None,
                default_argon2_params()?
            )?,
            r#"a-BB&E293:RFFF7brF30F91F9BE,90DCEyFg.88,1C9C02-<"#,
        );
        assert_eq!(
            &*generate_pass_without_repeats(
                None,
                "bong",
                "bing",
                &0u32,
                None,
                default_argon2_params()?
            )?,
            r#"ec14D9O8ACE9F\82C7cC5D6D01E98EB4B29?m3968F8BC1E0FBDF6"#,
        );
        assert_eq!(
            &*generate_pass_with_repeats(
                None,
                "bong",
                "bing",
                &1u32,
                None,
                default_argon2_params()?
            )?,
            r#"(83a2EF89XB8B3C4E9E7WBQ04LA2O[{DEC6*03FFM88UF4F380C"#,
        );
        assert_eq!(
            &*generate_pass_without_repeats(
                None,
                "bong",
                "bing",
                &1u32,
                None,
                default_argon2_params()?
            )?,
            r#"feDCLF1E0LE6.w+868BE7F82cFq0A96E586C4B7wBF13ACE7D3NF1"#,
        );
        assert_eq!(
            &*generate_pass_with_repeats(
                None,
                "bong",
                "bing",
                &2u32,
                None,
                default_argon2_params()?
            )?,
            r#"c0BC818F92D8E5\0DB2F9D5-EB84B7FF02NBC91999DW,ZB8A9BBF3EFF7"#,
        );
        assert_eq!(
            &*generate_pass_without_repeats(
                None,
                "bong",
                "bing",
                &2u32,
                None,
                default_argon2_params()?
            )?,
            r#"y|(C301vDAFCD1D5j;EFD9D67FA8#B2C8vE4A3RF7CD93`8ELY"#,
        );
        assert_eq!(
            &*generate_pass_with_repeats(
                Some(0.6),
                "secret",
                "example.com",
                &0u32,
                None,
                default_argon2_params()?
            )?,
            r#"L1dRD2D6>-krNF0CEE3p/"13Q9+1DD7V?8C2A4A6k'07n"#,
        );
        assert_eq!(
            &*generate_pass_without_repeats(
                Some(0.6),
                "secret",
                "example.com",
                &0u32,
                None,
                default_argon2_params()?
            )?,
            r#"91f8uvm=A4?97w@1B1A20Fg_[C3D689&A4qB8:!BC\hm>"#,
        );
        assert_eq!(
            &*generate_pass_with_repeats(
                Some(0.55),
                "secret",
                "example.com",
                &1u32,
                None,
                default_argon2_params()?
            )?,
            r#".a3DBD2FFA289'E52|"7C6'z9F1E~D190C2Pp0296`|B69A="#,
        );
        assert_eq!(
            &*generate_pass_without_repeats(
                Some(0.55),
                "secret",
                "example.com",
                &1u32,
                None,
                default_argon2_params()?
            )?,
            r#"f0tCBA8C8D4x|{Dv2091+*F0F0B6384FA915ADX:gt8A8NBD"#,
        );
        Ok(())
    }

    fn default_argon2_params() -> anyhow::Result<argon2::Params> {
        let params = argon2::Params::new(argon2::Params::DEFAULT_M_COST, 3, 1, Some(32))
            .map_err(Error::Argon2)?;
        Ok(params)
    }
}
