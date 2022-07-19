use anyhow::Result;
use base64::encode;
use clap::{Arg, Command};
use open;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use openssl::{ec::EcGroup, ec::EcKey};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sigstore::oauth;
use std::io::{Read};
use std::time::Duration;
use std::{fs::File, io::Write};

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

fn main() -> Result<(), anyhow::Error> {
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
            Arg::new("cert")
                .short('c')
                .long("cert")
                .takes_value(true)
                .help("Output signing certificate"),
        )
        .arg(
            Arg::new("file")
                .short('f')
                .long("file")
                .required(true)
                .takes_value(true)
                .help("Output signing certificate"),
        )
        .arg(
            Arg::new("signature")
                .short('n')
                .long("signature")
                .required(true)
                .takes_value(true)
                .help("Output signature"),
        )
        .get_matches();

    // set up keys
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let private_key = EcKey::generate(&group).unwrap();
    let key = PKey::from_ec_key(private_key.clone())?;

    let public_key = private_key.public_key();
    let ec_pub_key = EcKey::from_public_key(&group, public_key).unwrap();
    let public_key_pem = &ec_pub_key.public_key_to_pem().unwrap();

    if matches.is_present("sign") {
        let oidc_url = oauth::openidflow::OpenIDAuthorize::new(
            "sigstore",
            "",
            SIGSTORE_OAUTH_URL,
            "http://localhost:8080",
        )
        .auth_url()?;

        if open::that(oidc_url.0.to_string()).is_ok() {
            println!(
                "Open this URL in a browser if it does not automatically open for you:\n{}\n",
                oidc_url.0.to_string()
            );
        }

        let result = oauth::openidflow::RedirectListener::new(
            "127.0.0.1:8080",
            oidc_url.1, // client
            oidc_url.2, // nonce
            oidc_url.3, // pkce_verifier
        )
        .redirect_listener();

        let (token_response, id_token) = result?;
        let email = token_response.email().unwrap();
        println!("Received token for email scope: {}", email.to_string());

        let mut signer = Signer::new(MessageDigest::sha256(), &key).unwrap();
        signer.update(&email.to_string().as_bytes()).unwrap();

        let signature = signer.sign_to_vec().unwrap();

        let params = FulcioPayload {
            public_key: PubKey {
                content: encode(public_key_pem.to_vec()),
                algorithm: String::from("ecdsa"),
            },
            signed_email_address: encode(&signature),
        };

        let body = serde_json::to_string(&params).unwrap();
        println!("Requesting signing certificate from Fulcio...");

        let client = reqwest::blocking::Client::new();
        let response = client
            .post(FULCIO_URL)
            .header("Authorization", format!("Bearer {}", id_token.to_string()))
            .header("Content-Type", "application/json")
            .timeout(Duration::from_secs(120))
            .body(body)
            .send()?;
        let certs = response.text()?;

        // stick the signers cert into here (based on it being 'sigstore-intermediate')
        let mut cert_pem = String::new();

        let cert_re =
            Regex::new(r#"-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----"#).unwrap();
        for capture in cert_re.find_iter(&String::from_utf8(certs.as_bytes().to_vec()).unwrap()) {
            let cert = openssl::x509::X509::from_pem(capture.as_str().as_bytes()).unwrap();
            for jk in cert.issuer_name().entries() {
                if matches.is_present("cert") {
                    // print the value of file
                    if jk.data().as_slice() == b"sigstore-intermediate" {
                        let filename = matches.value_of("cert").unwrap();
                        let mut file = File::create(filename).unwrap();
                        cert_pem.push_str(capture.as_str());
                        file.write_all(capture.as_str().as_bytes()).unwrap();
                    }
                }
            }
        }
        println!("Saving signing cerificate to {}", matches.value_of("cert").unwrap());
        // println!("{}", cert_pem);
        println!("Signing file {}", matches.value_of("file").unwrap());
        let filename = matches.value_of("file").unwrap();
        let signature_filename = matches.value_of("signature").unwrap();
        // sign filename
        let mut file = File::open(filename).unwrap();
        let mut file_signer = Signer::new(MessageDigest::sha256(), &key).unwrap();
        // convert file to bytes
        let mut file_bytes = Vec::new();
        file.read_to_end(&mut file_bytes).unwrap();
        file_signer.update(&file_bytes).unwrap();
        let signature = file_signer.sign_to_vec().unwrap();
        let mut file = File::create(signature_filename).unwrap();
        // write signature to file
        file.write_all(&signature).unwrap();
        println!("Saving signature to {}", signature_filename);
        question::Question::new("Submit signing entries rekor (Y/N)?").confirm();
    }
    anyhow::Ok(())
}
