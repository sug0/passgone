mod error;
mod gen;

use std::num::NonZeroU32;

use clap::Parser;
use rpassword::prompt_password;
use zeroize::Zeroizing;

use self::error::Error;
use self::gen::v0;

const PROMPT: &str = "mnemonic: ";
const PROMPT_CONFIRM: &str = "confirm: ";

/// Password generator based on mnemonics
#[derive(Clone, Parser, Debug)]
#[command(version, about, long_about = None)]
struct Arguments {
    /// Disable repeated characters in sequence in the
    /// generated password
    ///
    /// By default, this flag is disabled
    #[arg(long, default_value_t = false)]
    no_repetitions: bool,
    /// Confirm mnemonic input
    ///
    /// This option only makes sense when reading
    /// from stdin
    #[arg(long, default_value_t = false)]
    confirm: bool,
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
    let counter = scopeguard::guard(args.counter, |mut counter| {
        // scuffed zeroizing of the counter
        unsafe {
            std::ptr::write_volatile(&mut *counter as *mut _, 0u32);
        }
    });

    let params = argon2::Params::new(
        argon2::Params::DEFAULT_M_COST,
        args.iterations.get(),
        args.threads.get(),
        Some(args.hash_length),
    )
    .map_err(Error::Argon2)?;

    let mnemonic = args.mnemonic.map_or_else(
        || {
            let read = prompt_password(PROMPT)
                .map(Zeroizing::new)
                .map_err(Error::Io)?;
            if !args.confirm {
                return Ok(read);
            }
            let confirmed = prompt_password(PROMPT_CONFIRM)
                .map(Zeroizing::new)
                .map_err(Error::Io)?;
            if read != confirmed {
                return Err(Error::MnemonicMismatch);
            }
            Ok(confirmed)
        },
        Ok,
    )?;
    let output_pass = if args.no_repetitions {
        v0::generate_pass_without_repeats(&mnemonic, &args.salt, &counter, params)?
    } else {
        v0::generate_pass_with_repeats(&mnemonic, &args.salt, &counter, params)?
    };

    println!("{}", output_pass.as_str());
    Ok(())
}
