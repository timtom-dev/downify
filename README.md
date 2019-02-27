# Downify

Downify is a small Rust library for downloading, signing, and verifying files.

The library uses reqwest to download a file from a URL and hashes it with blake2-rfc as it downloads. Sodiumoxide is then used to verify the file's signed hash before returning a `VerifiedFile` handle.

Downloads can optionally be resumed from servers that support the HTTP Range header. By default the library forces HTTPS, and fails if a secure connection cannot be established.

Sodiumoxide's keys and signatures are encoded with base64's URL_SAFE_NO_PAD for storage/transfer.
Public keys are prepended with "DYP1"
Secret keys are prepended with "DYS1"
Signatures are prepended with "DYG1"

A command-line interface to the library, with options based on OpenBSD's Signify, is included.
