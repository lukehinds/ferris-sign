use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::{ec::EcGroup, ec::EcKey};
use openssl::sign::{Signer};
use openssl::hash::MessageDigest;

fn create_keys() -> Result<(), openssl::error::ErrorStack> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let private_key = EcKey::generate(&group).unwrap();
    let key = PKey::from_ec_key(private_key.clone())?;

    let public_key = private_key.public_key();
    let ec_pub_key = EcKey::from_public_key(&group, public_key)?;
    let public_key_pem = &ec_pub_key.public_key_to_pem()?;
    println!("{}", public_key_pem);
    Ok(())
}


fn create_signer() -> Result<(), openssl::error::ErrorStack> {
    let mut signer = Signer::new(MessageDigest::sha256(), &key).unwrap();
    signer.update(&email.to_string().as_bytes()).unwrap();
    Ok(())
}
