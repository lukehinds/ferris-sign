use base64::{encode};
use clap::{Command, Arg};
use anyhow::Result;
use std::time::Duration;
use sigstore::oauth;
use open;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::{ec::EcGroup, ec::EcKey};
use openssl::sign::{Signer};
use openssl::hash::MessageDigest;
use serde::{Serialize, Deserialize};

const FULCIO_URL: &str = "https://fulcio.sigstore.dev/api/v1/signingCert";
const SIGSTORE_OAUTH_URL: &str = "https://oauth2.sigstore.dev/auth";

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FulcioPayload {
    pub public_key: PublicKey,
    pub signed_email_address: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKey {
    pub content: String,
    pub algorithm: String,
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
        .get_matches();

        if matches.is_present("sign") {

            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
            let private_key = EcKey::generate(&group).unwrap();
            let key = PKey::from_ec_key(private_key.clone())?;

            let public_key = private_key.public_key();
            let ec_pub_key = EcKey::from_public_key(&group, public_key).unwrap();
            let public_key_pem = &ec_pub_key.public_key_to_pem().unwrap();
            // println!("{}", String::from_utf8(public_key_pem.to_vec()).unwrap());
            // let encoded_pub = encode(public_key_pem.to_vec());

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
            
            let mut signer = Signer::new(MessageDigest::sha256(), &key).unwrap();
            signer.update(&email.to_string().as_bytes()).unwrap();

            let signature = signer.sign_to_vec().unwrap();
            println!("Signature: {}", encode(&signature));

            let params = FulcioPayload {
                public_key: PublicKey {
                    content: encode(public_key_pem.to_vec()),
                    algorithm: String::from("ecdsa"),
                },
                signed_email_address: encode(&signature),
            };

            let body = serde_json::to_string(&params).unwrap();
            println!("body: {}", body);

            let client = reqwest::blocking::Client::new();
            let response = client
                .post(FULCIO_URL)
                .header("Authorization", format!("Bearer {}", id_token.to_string()))
                .header("Content-Type", "application/json")
                .timeout(Duration::from_secs(120))
                .body(body)
                .send()?;
            println!("create_ref HTTP code {:?}", response.status());
            // print the response body
            let body = response.text()?;
            println!("create_ref response body {:?}", body);

            // let certs = body.split_whitespace();
            // for cert in certs {
            //     println!("{}", cert);
            // }
            
        }
    anyhow::Ok(())
}

