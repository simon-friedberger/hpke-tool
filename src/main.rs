use base64::{engine::general_purpose, Engine};
use hpke::{
    aead::{AeadTag, ChaCha20Poly1305},
    generic_array::{typenum, GenericArray},
    kdf::HkdfSha384,
    kem::X25519HkdfSha256,
    Deserializable, Kem, OpModeR, OpModeS, Serializable,
};
use rand::{Rng, SeedableRng};

fn print_key(key_by: &GenericArray<u8, typenum::U32>, name: &str) {
    println!("Key ({}):", name);
    println!("  hex: {:x}", key_by);
    let key_b64 = general_purpose::URL_SAFE_NO_PAD.encode(key_by);
    println!("  b64: {:?}", key_b64);
}

fn generate_keys() {
    let mut rng = rand::rngs::StdRng::from_entropy();
    let (privkey, pubkey) = X25519HkdfSha256::gen_keypair(&mut rng);
    print_key(&privkey.to_bytes(), "Private");
    print_key(&pubkey.to_bytes(), "Public");

    roundtrip_test(privkey, pubkey);
}

fn parse_key(text: &str) -> Vec<u8> {
    let key = general_purpose::URL_SAFE_NO_PAD.decode(text).unwrap();
    print_key(GenericArray::from_slice(&key), "parsed");
    key
}

fn roundtrip_test_hardcoded() {
    println!("Hardcoded roundtrip test:");
    let privkey = "kPKoZjqKrhXQcunyn7HyMiSIuWFqROFtsI2kACcDEW4";
    println!("Private key: {}", privkey);
    let privkey = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&parse_key(privkey)).unwrap();

    let pubkey = "04XosIh9DlZ5FdSUnz3pFWyDk8m0lowdNP62QjiHaXM";
    println!("Public key: {}", pubkey);
    let pubkey = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&parse_key(pubkey)).unwrap();

    roundtrip_test(privkey, pubkey);
}

fn roundtrip_test(
    privkey: <X25519HkdfSha256 as Kem>::PrivateKey,
    pubkey: <X25519HkdfSha256 as Kem>::PublicKey,
) {
    print!("Roundtrip test ");
    let mut msg = [0u8; 300];
    rand::thread_rng().fill(&mut msg[..]);
    let mut aad = [0u8; 100];
    rand::thread_rng().fill(&mut aad[..]);
    let (encapped_key, ciphertext, tag) = encrypt(pubkey, &msg, &aad);
    let decrypted = decrypt(privkey, encapped_key, ciphertext, tag, &aad);
    assert_eq!(decrypted, msg);
    println!("…succeeded.");
}

fn encrypt(
    pubkey: <X25519HkdfSha256 as Kem>::PublicKey,
    msg: &[u8],
    aad: &[u8],
) -> (
    <X25519HkdfSha256 as Kem>::EncappedKey,
    // ^ note that we need to specify the trait for which we want the associated type even if there is only one trait
    Vec<u8>,
    AeadTag<ChaCha20Poly1305>,
) {
    let mut csprng = rand::rngs::StdRng::from_entropy();
    let (encapped_key, mut sender_ctx) = hpke::setup_sender::<
        ChaCha20Poly1305,
        HkdfSha384,
        X25519HkdfSha256,
        _,
    >(&OpModeS::Base, &pubkey, b"Info String", &mut csprng)
    .expect("Key encapsulation failed");

    let mut msg_copy = msg.to_vec();
    let tag = sender_ctx
        .seal_in_place_detached(&mut msg_copy, &aad)
        .expect("Encryption failed!");
    let ciphertext = msg_copy;

    (encapped_key, ciphertext, tag)
}

fn decrypt(
    privkey: <X25519HkdfSha256 as Kem>::PrivateKey,
    encapped_key: <X25519HkdfSha256 as Kem>::EncappedKey,
    ciphertext: Vec<u8>,
    tag: AeadTag<ChaCha20Poly1305>,
    aad: &[u8],
) -> Vec<u8> {
    let mut receiver_ctx = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha384, X25519HkdfSha256>(
        &OpModeR::Base,
        &privkey,
        &encapped_key,
        b"Info String",
    )
    .expect("Decapsulation failed!");

    let mut ciphertext_copy = ciphertext.to_vec();
    receiver_ctx
        .open_in_place_detached(&mut ciphertext_copy, aad, &tag)
        .expect("invalid ciphertext!");

    let plaintext = ciphertext_copy;

    plaintext
}

fn main() {
    generate_keys();
    //roundtrip_test_hardcoded();
}
