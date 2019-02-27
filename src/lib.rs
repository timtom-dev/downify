extern crate reqwest;
extern crate base64;

use std::str::FromStr;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::io::SeekFrom;
use std::error::Error;

use reqwest::header::{CONTENT_LENGTH, RANGE};
use base64::URL_SAFE_NO_PAD;
use blake2_rfc::blake2b::Blake2b;
use sodiumoxide::crypto::sign::ed25519;
use sodiumoxide::crypto::sign::ed25519::verify_detached;

pub type VerifiedFile = File;

pub struct Progress {
    pub completed_bytes: usize,
    pub total_bytes: usize,
}

pub struct Context<'a> {
    source_url: &'a str,
    dest_path: &'a str,
    dest_file: File,
    public_key: ed25519::PublicKey,
    expected_sig: ed25519::Signature,
    hash_context: Blake2b,
    client: reqwest::Client,
    completed_bytes: usize,
    content_length: usize,
    chunksize: usize,
}

impl<'a> Context<'a> {
    pub fn new(source_url: &'a str,
               dest_path: &'a str,
               expected_sig: &'a str,
               public_key: &'a str,
               chunksize: usize) -> Result<Self, Box<Error>> {

        let public_key = decode_public_key(public_key).unwrap();
        let expected_sig = decode_signature(expected_sig).unwrap();

        let dest_file = File::create(dest_path)?;

        let client = reqwest::Client::new();
        let response = client.head(source_url).send()?;

        let length = response
            .headers()
            .get(CONTENT_LENGTH)
            .ok_or("Response doesn't include Content-Length")?;
        let length = usize::from_str(length.to_str()?).map_err(|_| "invalid Content-Length header")?;

        Ok(Context {
            source_url: source_url,
            dest_path: dest_path,
            dest_file: dest_file,
            public_key: public_key,
            expected_sig: expected_sig,
            hash_context: Blake2b::new(32),
            client: client,
            completed_bytes: 0 as usize,
            content_length: length,
            chunksize: chunksize,
        })
    }

    /// Download next chunk and update hash
    pub fn step(&mut self) -> Result<Progress, Box<Error>> {
        // Download chunk
        let data = self.client
            .get(self.source_url)
            .header(RANGE, format!("{}-{}", self.completed_bytes, self.completed_bytes + self.chunksize))
            .send()?
            .text()?;
       
        // Hash chunk
        self.hash_context.update(&data.as_bytes());

        // Write chunk to disk
        self.dest_file.write(&data.as_bytes())?;
        
        // Update context
        self.completed_bytes += data.len();

        Ok(Progress { completed_bytes: self.completed_bytes, total_bytes: self.content_length })
    }

    /// Consume context, verify hash, and return `VerifiedFile` handle
    pub fn finish(mut self) -> Option<VerifiedFile> {
        let hash = self.hash_context.finalize();

        // Verify signature
        if verify_detached(&self.expected_sig, hash.as_bytes(), &self.public_key) {
            // Seek to the start of the file before returning the handle
            self.dest_file.seek(SeekFrom::Start(0)).unwrap();
            Some(self.dest_file)
        } else {
            // Close and delete the invalid file
            drop(self.dest_file);
            fs::remove_file(self.dest_path).unwrap();
            None
        }
    }
}

/// Generate a keypair
pub fn gen_keypair() -> (String, String) {
    sodiumoxide::init().unwrap();
    let (pk, sk) = ed25519::gen_keypair();

    (format!("DYP1{}", base64::encode_config(&pk[..], URL_SAFE_NO_PAD)),
     format!("DYS1{}", base64::encode_config(&sk[..], URL_SAFE_NO_PAD)))
}

/// Sign a file with a secret key
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

/// Open file and verify before returning a file handle
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

    // Verify signature
    if verify_detached(&expected_sig, hash, &public_key) {
        file.seek(SeekFrom::Start(0)).unwrap();
        Some(file as VerifiedFile)
    } else {
        None
    }
}

/// Download file to buffer and verify before writing to destination
pub fn verify_get(source_url: &str, dest_path: &str, expected_sig: &str, public_key: &str) -> Option<VerifiedFile> {
    let public_key = decode_public_key(public_key).unwrap();
    let expected_sig = decode_signature(expected_sig).unwrap();

    // Download file
    let mut buffer = Vec::new();
    let mut resp = reqwest::get(source_url).unwrap();
    resp.read_to_end(&mut buffer).unwrap();
    
    // Hash file
    let mut context = Blake2b::new(32);
    context.update(&buffer);
    let hash = context.finalize();

    // Verify hash
    if verify_detached(&expected_sig, &hash.as_bytes(), &public_key) {
        // Write file once data is verified
        let mut dest_file = File::create(dest_path).unwrap();
        dest_file.seek(SeekFrom::Start(0)).unwrap();
    
        Some(dest_file)
    } else {
        None
    }
}

fn decode_public_key(public_key: &str) -> Option<ed25519::PublicKey> {
    match &public_key[0..4] {
        "DYP1" => ed25519::PublicKey::from_slice(
                match base64::decode_config(&public_key[4..], URL_SAFE_NO_PAD) {
                    Ok(x) => x,
                    Err(_) => return None,
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
                    Err(_) => return None,
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
                    Err(_) => return None,
                }.as_slice(),
            ),
        _ => None,
    }
}
