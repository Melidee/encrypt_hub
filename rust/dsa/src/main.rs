use ring::{
    rand,
    signature::{self, KeyPair},
};

// Generate a key pair in PKCS#8 (v2) format.
let rng = rand::SystemRandom::new();
let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng)?;

// Normally the application would store the PKCS#8 file persistently. Later
// it would read the PKCS#8 file from persistent storage to use it.

let key_pair =
    signature::Ed25519KeyPair::from_pkcs8(untrusted::Input::from(pkcs8_bytes.as_ref()))?;

// Sign the message "hello, world".
const MESSAGE: &[u8] = b"hello, world";
let sig = key_pair.sign(MESSAGE);

// Normally an application would extract the bytes of the signature and
// send them in a protocol message to the peer(s). Here we just get the
// public key key directly from the key pair.
let peer_public_key_bytes = key_pair.public_key().as_ref();
let sig_bytes = sig.as_ref();

// Verify the signature of the message using the public key. Normally the
// verifier of the message would parse the inputs to `signature::verify`
// out of the protocol message(s) sent by the signer.
let peer_public_key = untrusted::Input::from(peer_public_key_bytes);
let msg = untrusted::Input::from(MESSAGE);
let sig = untrusted::Input::from(sig_bytes);

signature::verify(&signature::ED25519, peer_public_key, msg, sig)?;
