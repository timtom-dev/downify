# Downify

[![crates.io](https://img.shields.io/crates/v/downify.svg)](https://crates.io/crates/downify)
[![docs](https://docs.rs/downify/badge.svg)](https://docs.rs/downify)

Downify is a small Rust library for downloading, signing, and verifying files.

The library uses reqwest to download a file from a URL and hashes it with blake2-rfc. Sodiumoxide is then used to verify the file's signed hash before returning a `VerifiedFile` handle.

Sodiumoxide's keys and signatures are encoded with base64's URL_SAFE_NO_PAD for storage/transfer.
 - Public keys are prepended with "DYP1"
 - Secret keys are prepended with "DYS1"
 - Signatures are prepended with "DYG1"

A command-line interface to the library, with options based on OpenBSD's Signify, is included.

### Examples

```
extern crate downify;

// Generate a keypair
let (public_key, secret_key) = downify::gen_keypair();

// Sign a file
let signature = downify::sign("/source/path", &secret_key);

// Verify a local file
let file_handle = downify::verify_open("/source/path", &signature, &public_key).unwrap();

// Verify a remote file
let file_handle = verify_get("https://www.example.com/", "/destination/path", &signature, &public_key).unwrap();
```
