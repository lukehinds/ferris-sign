use anyhow::Result;
use base64::encode;
use clap::{Arg, Command};
use open;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sigstore::oauth;
use std::io::Read;
use std::path::PathBuf;
use std::{fs::File, io::Write};
use tokio::task;

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
            Arg::new("generate-keys")
                .short('k')
                .long("generate-keys")
                .takes_value(false)
                .help("Generate key pair"),
        )
        .arg(
            Arg::new("sign")
                .short('s')
                .long("sign")
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
                .required(true)
                .takes_value(true)
                .help("Location of file to sign"),
        )
        .arg(
            Arg::new("sig-out")
                .short('o')
                .long("sig-out")
                .required(true)
                .takes_value(true)
                .help("Location to place signature output"),
        )
        .get_matches();

    let (private_key, public_key_pem) = crypto::create_keys()?;
    let mut scope_signer = crypto::create_signer(&private_key)?;

    if matches.is_present("sign") {
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
                "Open this URL in a browser if it does not automatically open for you:\n{}\n",
                oidc_url.0.to_string()
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
        println!("Received token for email scope: {}", email.to_string());

        scope_signer.update(&email.to_string().as_bytes()).unwrap();

        let signature = scope_signer.sign_to_vec().unwrap();

        let params = FulcioPayload {
            public_key: PubKey {
                content: encode(&public_key_pem),
                algorithm: String::from("ecdsa"),
            },
            signed_email_address: encode(&signature),
        };

        let body = serde_json::to_string(&params).unwrap();
        println!("Requesting signing certificate from Fulcio...");

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
            "Saving signing cerificate to {}",
            matches.value_of("cert-out").unwrap()
        );

        let filename = matches.value_of("in-file").unwrap();

        let signature_filename = matches.value_of("sig-out").unwrap();
        // sign filename
        let mut file = File::open(filename).unwrap();

        let mut file_signer = crypto::create_signer(&private_key)?;
        let mut file_bytes = Vec::new();
        file.read_to_end(&mut file_bytes).unwrap();
        file_signer.update(&file_bytes).unwrap();
        let signature = file_signer.sign_to_vec().unwrap();

        let mut file = File::create(signature_filename).unwrap();
        // write signature to file
        file.write_all(&signature).unwrap();
        println!("Saving signature to {}", signature_filename);
        // print signature to stdout

        // convert signature to base64
        let signature_base64 = encode(&signature);
        let public_key_base64 = encode(&public_key_pem);

        // send to rekor
        let hash = crypto::sha256_digest(PathBuf::from(filename))?;

        println!("Sending signature artifacts to rekor...");
        let log_entry = rekor_api::create_log(&hash, &public_key_base64, &signature_base64).await;
        println!("{:#?}", log_entry);
    }
    anyhow::Ok(())
}
