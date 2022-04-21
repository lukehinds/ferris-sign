mod crypto;
use base64::{encode, decode};
use clap::{Command, Arg};
use anyhow::Result;
use sigstore::oauth;
use open;

const FULCIO_URL: &str = "https://fulcio.sigstore.dev/api/v1/signingCert";
const SIGSTORE_OAUTH_URL: &str = "https://oauth2.sigstore.dev/auth";

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

            let pub_key = encode(crypto::generate_keys());
            println!("{}", pub_key);

            // let oidc_url = oauth::openidflow::OpenIDAuthorize::new(
            //     "sigstore",
            //     "",
            //     SIGSTORE_OAUTH_URL,
            //     "http://localhost:8080",
            // )
            // .auth_url();

            // if open::that(oidc_url.0.to_string()).is_ok() {
            //     println!(
            //         "Open this URL in a browser if it does not automatically open for you:\n{}\n",
            //         oidc_url.0.to_string()
            //     );
            // }
        
            // let result = oauth::openidflow::RedirectListener::new(
            //     "127.0.0.1:8080",
            //     oidc_url.1, // client
            //     oidc_url.2, // nonce
            //     oidc_url.3, // pkce_verifier
            // )
            // .redirect_listener();

            // match result {
            //     Ok(token_response) => {
            //         println!("Email {:?}", token_response.email().unwrap().to_string());
            //         println!(
            //             "Access Token:{:?}",
            //             token_response.access_token_hash().unwrap().to_string()
            //         );
            //     }
            //     Err(err) => {
            //         println!("{}", err);
            //     }
            // }

        }
    anyhow::Ok(())
}

