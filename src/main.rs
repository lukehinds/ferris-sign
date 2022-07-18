use base64::{encode};
use clap::{Command, Arg};
use anyhow::Result;
use std::{fs::File, io::Write, io::copy};
use std::time::Duration;
use sigstore::oauth;
use regex::Regex;
use open;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::{ec::EcGroup, ec::EcKey};
use openssl::sign::{Signer};
use openssl::hash::MessageDigest;
use serde::{Serialize, Deserialize};
use data_encoding::HEXLOWER;
use sha2::{Digest, Sha256};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use rekor::apis::{configuration::Configuration, entries_api};
use rekor::models::{
    hashedrekord::{AlgorithmKind, Data, Hash, PublicKey, Signature, Spec},
    ProposedEntry,
};
use url::Url;

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


/// calculates sha256 digest as lowercase hex string
fn sha256_digest(path: PathBuf) -> Result<String> {
    let input = File::open(path)?;
    let mut reader = BufReader::new(input);

    let digest = {
        let mut hasher = Sha256::new();
        let mut buffer = [0; 1024];
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 { break }
            hasher.update(&buffer[..count]);
        }
        hasher.finalize()
    };
    Ok(HEXLOWER.encode(digest.as_ref()))
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
                .takes_value(true)
                .help("Output signing certificate")
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
                    "Open this URL in a browser if it does not automatically open for you:\n\n{}\n",
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
            // println!("body: {}", body);

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

            let cert_re = Regex::new(r#"-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----"#).unwrap(); 
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
            // println!("{}", cert_pem);
            // rekor
            
        }
        let digest = Sha256::new();
        if matches.is_present("file") {
            let filename = matches.value_of("file").unwrap();
            let digest = sha256_digest(PathBuf::from(filename))?;
            println!("{}", digest);
        }
        println!("{:?}", digest);

    anyhow::Ok(())
}
