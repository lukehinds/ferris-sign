use openssl::nid::Nid;
use openssl::{ec::EcGroup, ec::EcKey};

// geneate key pair and return public key
pub fn generate_keys() -> String {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let private_key = EcKey::generate(&group).unwrap();

    let public_key = private_key.public_key();
    let ec_pub_key = EcKey::from_public_key(&group, public_key).unwrap();
    let public_key_pem = &ec_pub_key.public_key_to_pem().unwrap();
    String::from_utf8(public_key_pem.clone().to_vec()).unwrap()
}