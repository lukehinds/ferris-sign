use anyhow::Result;
use base64::{decode, encode};
use clap::{Arg, Command};
use colored::Colorize;
use openssl::ec::EcKey;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Verifier;
use openssl::x509::X509;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sigstore::oauth;
use std::io::Read;
use std::path::PathBuf;
use std::{fs::File, io::Write};
use tokio::task;

use sigstore::crypto::SigningScheme;
use sigstore::fulcio::FulcioCert;

mod crypto;
mod rekor_api;
extern crate question;

const FULCIO_URL: &str = "https://fulcio.sigstore.dev/api/v1/signingCert";
const SIGSTORE_OAUTH_URL: &str = "https://oauth2.sigstore.dev/auth";

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FulcioPayload {
    pub public_key: PubKey,
    pub signed_email_address: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PubKey {
    pub algorithm: String,
    pub content: String,
}
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let matches = Command::new("ferris-sign")
        .version("0.1")
        .author("Luke Hinds")
        .about("Simple rust based example of sigstore signing")
        .arg(
            Arg::new("sign")
                .short('s')
                .long("sign")
                .requires("in-file")
                .requires("sig-out")
                .requires("cert-out")
                .takes_value(false)
                .help("OIDC sign"),
        )
        .arg(
            Arg::new("cert-out")
                .short('c')
                .long("cert-out")
                .takes_value(true)
                .help("Location to place signing certificate output"),
        )
        .arg(
            Arg::new("in-file")
                .short('i')
                .long("in-file")
                .takes_value(true)
                .help("Location of file to sign"),
        )
        .arg(
            Arg::new("sig-out")
                .short('o')
                .long("sig-out")
                .takes_value(true)
                .help("Location to place signature output"),
        )
        .arg(
            Arg::new("extract")
                .short('e')
                .long("extract")
                .takes_value(true)
                .help("Extract public key from Fulcio signing certificate"),
        )
        .arg(
            Arg::new("verify")
                .short('v')
                .long("verify")
                .takes_value(false)
                .help("Verify a signature on a file"),
        )
        .arg(
            Arg::new("sig-in")
                .long("sig-in")
                .takes_value(true)
                .help("Path to signature file for verification"),
        )
        .arg(
            Arg::new("pubkey")
                .long("pubkey")
                .takes_value(true)
                .help("Path to pubkey file for verification"),
        )
        .arg(
            Arg::new("signed")
                .long("signed")
                .takes_value(true)
                .help("Path to signed file for verification"),
        )
        .get_matches();

    let signer = SigningScheme::ECDSA_P256_SHA256_ASN1.create_signer()?;

    if matches.is_present("extract") {
        // TODO: should this functionality be added to sigstore-rs?

        let cert_file = matches.value_of("extract").unwrap();
        let mut file = File::open(cert_file)?;
        let mut cert_data = Vec::new();
        file.read_to_end(&mut cert_data)?;

        let certificate = X509::from_pem(&cert_data)?;
        let pub_key_pem = certificate.public_key()?.public_key_to_pem()?;
        let pub_key_pem_string = String::from_utf8(pub_key_pem)?;

        println!("Extracted public key from Fulcio signing certificate file...\n");
        println!("{:?}", pub_key_pem_string);
    }

    if matches.is_present("sign") {
        let in_filename = matches.value_of("in-file").unwrap();
        let sig_filename = matches.value_of("sig-out").unwrap();
        let cert_filename = matches.value_of("cert-out").unwrap();

        // use tokio::task::spawn_blocking to call OpenIDAuthorize in a blocking thread
        let oidc_url = task::spawn_blocking(move || {
            oauth::openidflow::OpenIDAuthorize::new(
                "sigstore",
                "",
                SIGSTORE_OAUTH_URL,
                "http://localhost:8080",
            )
            .auth_url()
            .unwrap()
        })
        .await?;

        if open::that(oidc_url.0.to_string()).is_ok() {
            println!(
                "{}{}\n",
                format!(
                    "\nOpen this URL in a browser if it does not automatically open for you:\n"
                )
                .cyan(),
                oidc_url.0
            );
        }

        // use tokio::task::spawn_blocking to call RedirectListener in a blocking thread
        let result = task::spawn_blocking(move || {
            oauth::openidflow::RedirectListener::new(
                "127.0.0.1:8080",
                oidc_url.1, // client
                oidc_url.2, // nonce
                oidc_url.3, //
            )
            .redirect_listener()
            .unwrap()
        })
        .await?;

        // use tokio::task::spawn_blocking to call RedirectListener in a blocking thread
        let result = task::spawn_blocking(move || result).await?;

        let (token_response, id_token) = result;
        let email = token_response.email().unwrap();
        println!(
            "{} {:?}",
            format!("Received token for email scope: ").cyan(),
            email
        );

        let signature = signer.sign(email.to_string().as_bytes()).unwrap();

        let key_pair = signer.to_sigstore_keypair()?;
        let public_key_pem = key_pair.public_key_to_pem()?;
        let params = FulcioPayload {
            public_key: PubKey {
                content: encode(&public_key_pem),
                algorithm: String::from("ecdsa"),
            },
            signed_email_address: encode(&signature),
        };

        let body = serde_json::to_string(&params).unwrap();
        println!(
            "{}",
            format!("Requesting signing certificate from Fulcio...").cyan()
        );

        let client = reqwest::Client::new();
        let response = client
            .post(FULCIO_URL)
            .header("Authorization", format!("Bearer {}", id_token.to_string()))
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await?;
        let certs = response.text().await?;

        let mut cert_pem = String::new();

        let cert_re =
            Regex::new(r#"-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----"#).unwrap();
        for capture in cert_re.find_iter(&String::from_utf8(certs.as_bytes().to_vec()).unwrap()) {
            let cert = openssl::x509::X509::from_pem(capture.as_str().as_bytes()).unwrap();
            for jk in cert.issuer_name().entries() {
                if matches.is_present("cert-out") {
                    // print the value of file
                    if jk.data().as_slice() == b"sigstore-intermediate" {
                        let filename = matches.value_of("cert-out").unwrap();
                        let mut file = File::create(filename).unwrap();
                        cert_pem.push_str(capture.as_str());
                        file.write_all(capture.as_str().as_bytes()).unwrap();
                    }
                }
            }
        }
        println!(
            "{} {}",
            format!("Saving signing cerificate to ").cyan(),
            matches.value_of("cert-out").unwrap()
        );

        // sign in-file contents
        let mut file = File::open(in_filename).unwrap();
        let mut file_bytes = Vec::new();
        file.read_to_end(&mut file_bytes).unwrap();
        let signature = signer.sign(&file_bytes).unwrap();

        // write signature to file
        let mut file = File::create(sig_filename).unwrap();
        file.write_all(&signature).unwrap();
        println!(
            "{} {}",
            format!("Saving signature to ").cyan(),
            sig_filename
        );

        // read in bytes from cert file
        let mut cert_file_open = File::open(cert_filename).unwrap();
        let mut cert_file_bytes = Vec::new();
        cert_file_open.read_to_end(&mut cert_file_bytes).unwrap();

        // send to rekor, converting signature and cert to base64
        let signature_base64 = encode(&signature);
        let cert_file_base64 = encode(&cert_file_bytes);

        let hash = crypto::sha256_digest(PathBuf::from(in_filename))?;

        println!(
            "{}",
            format!("Sending signature artifacts to rekor... Created entry:\n").cyan()
        );
        let log_entry = rekor_api::create_log(&hash, &cert_file_base64, &signature_base64).await;
        println!("{:#?}", log_entry);

        // retrieve same entry from rekor
        let uuid = log_entry.unwrap().uuid;
        let retrieved_entry = rekor_api::get_entry_by_uuid(&uuid).await.unwrap();
        println!(
            "\n{} {}\n",
            format!("Retrieved log entry from Rekor by UUID ").cyan(),
            uuid
        );

        if matches.is_present("verify") {
            println!("{}",
                format!("Retrieving signature and Fulcio certificate from retrieved Rekor log entry...\n").cyan()
            );
            let spec = retrieved_entry.decode_body()?.spec;
            let signature = spec.signature.content;
            let decoded_fulcio_cert = spec.signature.public_key.decode()?;

            println!("{}", format!("Signature:").cyan());
            println!("{:?}\n\n", signature);
            println!("{}", format!("Public key (Fulcio cert):").cyan());
            println!("{:?}\n\n", decoded_fulcio_cert);

            println!(
                "\n{}\n",
                format!("Parsing public key from Fulcio certificate...").cyan()
            );
            let fulcio_cert = FulcioCert::new(&decoded_fulcio_cert);
            let pub_key = fulcio_cert.extract_pubkey_string()?;

            println!(
                "{} {:?}",
                format!("Extracted public key as base64 decoded string from Fulcio certificate:\n")
                    .cyan(),
                pub_key
            );

            // verify
            let ec_pubkey = EcKey::public_key_from_pem(pub_key.as_bytes())?;
            let pkey = PKey::from_ec_key(ec_pubkey)?;

            let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey)?;
            verifier.update(&file_bytes)?;

            println!("{}",
                format!("\nVerifying signature using sig from Rekor entry and pubkey from Fulcio certificate...\n\n").cyan());
            assert!(verifier.verify(&decode(signature)?)?);

            println!("{}", format!("VERIFICATION SUCCEEDED!\n\n").green());
        }
    }
    anyhow::Ok(())
}
