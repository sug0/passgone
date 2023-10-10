# passgone

A utility to generate passwords, via mnemonics and counters.

## Install

```
cargo install --git https://github.com/sug0/passgone
```

## Usage

Mnemonics and counters are the data points that should be kept safely.
The former are equivalent to regular passwords of sorts, while the latter may
be used e.g. if the generated passwords are compromised or a website requests a
password reset.

The following command will request a mnemonic from stdin, then output
a password to stdout:

```
passgone -s www.amazon.com --counter 0
```
By default, counters will be initialized to 0, so this flag is optional.
All the flags accepted by the program can be consulted with:

```
passgone --help
```
