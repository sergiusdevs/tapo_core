//! Differential test: the Rust port must reproduce, byte for byte, what the
//! python-kasa TPAP implementation computes for the same inputs.
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use serde::Deserialize;
use tapo_core::pake::{self, Register, Session};

#[derive(Deserialize)]
struct Reg {
    dev_random: String,
    dev_salt: String,
    dev_share: String,
    iterations: u32,
}

#[derive(Deserialize)]
struct Vectors {
    credentials_string: String,
    register: Reg,
    user_random: String,
    x_hex: String,
    user_share: String,
    user_confirm: String,
    expected_dev_confirm: String,
    shared_key: String,
    key: String,
    base_nonce: String,
    seq: u32,
    plaintext: String,
    ciphertext_and_tag: String,
}

fn b(s: &str) -> Vec<u8> {
    B64.decode(s).unwrap()
}

fn load() -> Vectors {
    serde_json::from_str(include_str!("vectors.json")).unwrap()
}

#[test]
fn spake2plus_matches_python() {
    let v = load();
    let reg = Register {
        dev_random: b(&v.register.dev_random),
        dev_salt: b(&v.register.dev_salt),
        dev_share: b(&v.register.dev_share),
        iterations: v.register.iterations,
    };
    let x = pake::scalar_from_hex(&v.x_hex).unwrap();
    let out = pake::build_share(&v.credentials_string, &b(&v.user_random), &reg, x).unwrap();
    assert_eq!(B64.encode(&out.user_share), v.user_share);
    assert_eq!(B64.encode(&out.user_confirm), v.user_confirm);
    assert_eq!(
        B64.encode(&out.expected_dev_confirm),
        v.expected_dev_confirm
    );
    assert_eq!(B64.encode(out.shared_key), v.shared_key);
}

#[test]
fn session_matches_python() {
    let v = load();
    let s = Session::from_shared_key(&b(&v.shared_key)).unwrap();
    let (key, nonce) = s.key_and_nonce();
    assert_eq!(B64.encode(key), v.key);
    assert_eq!(B64.encode(nonce), v.base_nonce);
    let sealed = s.seal(v.seq, v.plaintext.as_bytes()).unwrap();
    assert_eq!(B64.encode(&sealed), v.ciphertext_and_tag);
    assert_eq!(s.open(v.seq, &sealed).unwrap(), v.plaintext.as_bytes());
}

#[test]
fn tampered_ciphertext_is_rejected() {
    let v = load();
    let s = Session::from_shared_key(&b(&v.shared_key)).unwrap();
    let mut sealed = b(&v.ciphertext_and_tag);
    sealed[0] ^= 1;
    assert!(s.open(v.seq, &sealed).is_err());
}

fn register_with_share(share: Vec<u8>) -> Register {
    let v = load();
    Register {
        dev_random: b(&v.register.dev_random),
        dev_salt: b(&v.register.dev_salt),
        dev_share: share,
        iterations: v.register.iterations,
    }
}

#[test]
fn hostile_device_points_are_rejected() {
    let v = load();
    let x = || pake::scalar_from_hex(&v.x_hex).unwrap();
    let user_random = b(&v.user_random);
    // The identity element.
    let identity = register_with_share(vec![0u8]);
    assert!(pake::build_share("pw", &user_random, &identity, x()).is_err());
    // A well-formed encoding of a point that is not on the curve.
    let mut off_curve = vec![4u8];
    off_curve.extend([1u8; 64]);
    let r = register_with_share(off_curve);
    assert!(pake::build_share("pw", &user_random, &r, x()).is_err());
    // Zero PBKDF2 iterations.
    let mut zero = register_with_share(b(&v.register.dev_share));
    zero.iterations = 0;
    assert!(pake::build_share("pw", &user_random, &zero, x()).is_err());
}
