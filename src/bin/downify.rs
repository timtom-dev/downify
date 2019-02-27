extern crate downify;

#[macro_use]
extern crate structopt;

use std::fs;
use url::{Url, ParseError};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "Downify")]
/**A command-line interface to the Downify library.

SYNOPSIS:
    downify -G [-p pubkey] [-s seckey]
    downify -S [-x sigfile] [-s seckey] -m message
    downify -V [-x sigfile] [-p pubkey] -m message
    downify -R [-x sigfile] [-p pubkey] -u url
*/
struct Opt {
    /// Generate a new key pair.
    #[structopt(short = "G")]
    generate: bool,
    /// Sign the specified message file and create a signature.
    #[structopt(short = "S")]
    sign: bool,
    /// Verify that the local message and signature match.
    #[structopt(short = "V")]
    local: bool,
    /// Verify that the remote message and signature match.
    #[structopt(short = "R")]
    remote: bool,
    /// The file containing the message to sign or verify.
    #[structopt(short)]
    message: Option<String>,
    /// The URL to verify.
    #[structopt(short)]
    url: Option<String>,
    /// Public key produced by -G, and used by -V to check a signature.
    #[structopt(short, default_value = "publickey")]
    pubkey: String,
    /// Secret (private) key produced by -G, and used by -S to sign a message.
    #[structopt(short, default_value = "secretkey")]
    seckey: String,
    /// The signature file to create or verify.
    #[structopt(short = "x", default_value = "signature")]
    sigfile: String,
}

fn main() {
    let opt = Opt::from_args();

    let mut selected_modes = 0;
    if opt.generate { selected_modes += 1; }
    if opt.sign     { selected_modes += 1; }
    if opt.local    { selected_modes += 1; }
    if opt.remote   { selected_modes += 1; }
    if selected_modes != 1 {
        println!("Please use one of the -G, -S, or -V flags.");
        return;
    }

    // Generate a keypair
    if opt.generate {
        let (pk, sk) = downify::gen_keypair();

        fs::write(opt.pubkey, pk).expect("Unable to write public key.");
        fs::write(opt.seckey, sk).expect("Unable to write secret key.");

    // Sign a file
    } else if opt.sign {
        if opt.message.is_none() {
            println!("Please specify a file to sign with the -m option.");
            return;
        }

        let secret_key = fs::read_to_string(opt.seckey).expect("Unable to read secret key.");
        let signature = downify::sign(&opt.message.unwrap(), &secret_key);
        fs::write(opt.sigfile, signature).expect("Unable to write signature.");

    // Verify a local file
    } else if opt.local {
        if opt.message.is_none() {
            println!("Please specify a file to verify with the -m option.");
            return;
        }

        let signature = fs::read_to_string(opt.sigfile).expect("Unable to read signature.");
        let public_key = fs::read_to_string(opt.pubkey).expect("Unable to read public key.");
        let verified = downify::verify_open(&opt.message.unwrap(), &signature, &public_key);

        if verified.is_some() {
            println!("Verification Success");
        } else {
            println!("Verification Failed");
        }
        
    // TODO Verify a remote file
    } else if opt.remote {
        if opt.url.is_none() {
            println!("Please specify a URL to verify with the -u option.");
            return;
        }

        let signature = fs::read_to_string(opt.sigfile).expect("Unable to read signature.");
        let public_key = fs::read_to_string(opt.pubkey).expect("Unable to read public key.");
        let url_clone = opt.url.clone();
        let parsed_url = Url::parse(&url_clone.unwrap()).expect("Invalid URL");
        let dest = parsed_url.path_segments().unwrap().last().unwrap();
        let verified = downify::verify_get(&opt.url.unwrap(), &dest, &signature, &public_key);

        if verified.is_some() {
            println!("Verification Success");
        } else {
            println!("Verification Failed");
            // TODO delete file
        }
    }
}
