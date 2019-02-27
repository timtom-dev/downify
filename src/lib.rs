extern crate reqwest;
extern crate base64;

use std::fs::File;
use std::io::prelude::*;
use std::io::SeekFrom;

use base64::URL_SAFE_NO_PAD;
use blake2_rfc::blake2b::Blake2b;
use sodiumoxide::crypto::sign::ed25519;
use sodiumoxide::crypto::sign::ed25519::verify_detached;

pub type VerifiedFile = File;

pub struct Progress {
    completed_bytes: usize,
    total_bytes: Option<usize>,
}

pub struct Params {
    resume: bool,
    stream: bool,
    forcehttps: bool,
    chunksize: usize,
}

impl Params {
    pub fn new() -> Self {
        Params {
            resume: false,
            stream: true,
            forcehttps: true,
            chunksize: 8*1024,
        }
    }

    pub fn resume(mut self, new_value: bool) -> Self {
        self.resume = new_value;
        self
    }

    pub fn forcehttps(mut self, new_value: bool) -> Self {
        self.forcehttps = new_value;
        self
    }

    pub fn chunksize(mut self, new_value: usize) -> Self {
        self.chunksize = new_value;
        self
    }
}

pub struct Context<'a> {
    source_url: &'a str,
    dest_file: File,
    public_key: ed25519::PublicKey,
    expected_sig: ed25519::Signature,
    params: Params,
    completed_bytes: usize,
    hash: Option<Vec<u8>>,
    buffer: Vec<u8>,
}

impl<'a> Context<'a> {
    pub fn new(source_url: &'a str,
               dest_path: &'a str,
               public_key: &'a str,
               expected_sig: &'a str,
               params: Params) -> Self {

        let public_key = decode_public_key(public_key).unwrap();
        let expected_sig = decode_signature(expected_sig).unwrap();

        // TODO use temp file based on Params
        let dest_file = File::create(dest_path).unwrap();

        Context {
            source_url: source_url,
            dest_file: dest_file,
            public_key: public_key,
            expected_sig: expected_sig,
            params: params,
            completed_bytes: 0 as usize,
            hash: None,
            buffer: Vec::new(),
        }
    }

    // TODO don't do the whole thing at once
    // TODO use proper error type
    pub fn step(&mut self) -> Option<Progress> {
        // Download file
        let mut resp = reqwest::get(self.source_url).unwrap();
        resp.read_to_end(&mut self.buffer).unwrap();
    
        // Hash data
        let mut context = Blake2b::new(32);
        context.update(&self.buffer);
        let hash = context.finalize();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(hash.as_bytes());
        self.hash = Some(bytes);
    
        Some(Progress { completed_bytes: 0, total_bytes: None })
    }

    // Consume context, verify hash and return VerifiedFile if possible
    // TODO write to temp file as you go based on Params
    // TODO what happens if you call finish on a context that's not done?
    pub fn finish(mut self) -> Option<VerifiedFile> {
        // Verify signature
        if verify_detached(&self.expected_sig, &self.hash.unwrap(), &self.public_key) {
            // Write file once data is verified
            self.dest_file.seek(SeekFrom::Start(0)).unwrap();
            let bytes_written = self.dest_file.write(&self.buffer).unwrap();
    
            Some(self.dest_file)
        } else {
            None
        }

    }
}

pub fn gen_keypair() -> (String, String) {
    sodiumoxide::init().unwrap();
    let (pk, sk) = ed25519::gen_keypair();

    (format!("DYP1{}", base64::encode_config(&pk[..], URL_SAFE_NO_PAD)),
     format!("DYS1{}", base64::encode_config(&sk[..], URL_SAFE_NO_PAD)))
}

pub fn sign(file_path: &str, secret_key: &str) -> String {
    let secret_key = decode_secret_key(secret_key).unwrap();
    let mut file = File::open(file_path).unwrap();

    // Hash file
    //TODO Streaming file io
    let mut context = Blake2b::new(32);
    let mut file_data = Vec::new();
    file.read_to_end(&mut file_data).unwrap();
    context.update(&file_data);
    let hash = context.finalize();
    let hash = hash.as_bytes();

    // Sign hash
    let signature = ed25519::sign_detached(&hash, &secret_key);
    format!("DYG1{}", base64::encode_config(&signature[..], URL_SAFE_NO_PAD))
}

pub fn verify_open(file_path: &str, expected_sig: &str, public_key: &str) -> Option<VerifiedFile> {
    let public_key = decode_public_key(public_key).unwrap();
    let expected_sig = decode_signature(expected_sig).unwrap();

    let mut file = File::open(file_path).unwrap();

    // Hash file
    //TODO Streaming file io
    let mut context = Blake2b::new(32);
    let mut file_data = Vec::new();
    file.read_to_end(&mut file_data).unwrap();
    context.update(&file_data);
    let hash = context.finalize();
    let hash = hash.as_bytes();

    file.seek(SeekFrom::Start(0)).unwrap();

    // Verify signature
    if verify_detached(&expected_sig, hash, &public_key) {
        Some(file as VerifiedFile)
    } else {
        None
    }
}

// TODO this should probably have more descriptive error handling
pub fn verify_get(source_url: &str, dest_path: &str, expected_sig: &str, public_key: &str) -> Option<VerifiedFile> {
    let mut context = Context::new(source_url, dest_path, public_key, expected_sig, Params::new());
    context.step().unwrap();
    context.finish()
}

// TODO proper error type would mean ? operator and probably cleaner code, error types are useful anyway
fn decode_public_key(public_key: &str) -> Option<ed25519::PublicKey> {
    match &public_key[0..4] {
        "DYP1" => ed25519::PublicKey::from_slice(
                match base64::decode_config(&public_key[4..], URL_SAFE_NO_PAD) {
                    Ok(x) => x,
                    Err(x) => return None,
                }.as_slice(),
            ),
        _ => None,
    }
}

fn decode_secret_key(secret_key: &str) -> Option<ed25519::SecretKey> {
    match &secret_key[0..4] {
        "DYS1" => ed25519::SecretKey::from_slice(
                match base64::decode_config(&secret_key[4..], URL_SAFE_NO_PAD) {
                    Ok(x) => x,
                    Err(x) => return None,
                }.as_slice(),
            ),
        _ => None,
    }
}

fn decode_signature(signature: &str) -> Option<ed25519::Signature> {
    match &signature[0..4] {
        "DYG1" => ed25519::Signature::from_slice(
                match base64::decode_config(&signature[4..], URL_SAFE_NO_PAD) {
                    Ok(x) => x,
                    Err(x) => return None,
                }.as_slice(),
            ),
        _ => None,
    }
}
