//! TPAP crypto: SPAKE2+ over P-256 (cipher suite 1: SHA-256 + HMAC) and the
//! AES-128-CCM session. Ported from the python-kasa TPAP transport; only the
//! path used by Tapo bulbs (password auth, suite 1, aes_128_ccm) is implemented.

use std::fmt;

use aes::Aes128;
use ccm::Ccm;
use ccm::aead::{Aead, KeyInit, Payload};
use ccm::consts::{U12, U16};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::elliptic_curve::sec1::{FromSec1Point, ToSec1Point};
use p256::{AffinePoint, ProjectivePoint, Scalar, Sec1Point};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

const PAKE_CONTEXT_TAG: &[u8] = b"PAKE V1";
const M_COMPRESSED: &str = "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f";
const N_COMPRESSED: &str = "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49";

type Aes128Ccm = Ccm<Aes128, U16, U12>;
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug)]
pub enum Error {
    Protocol(String),
    Crypto(String),
    Http(String),
    Unsupported(String),
    /// The device answered with a non-zero `error_code`.
    Device {
        code: i64,
        message: String,
    },
    /// Client-side guard: we stopped talking to the device to avoid a lockout.
    Locked {
        retry_in_secs: u64,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Protocol(m) => write!(f, "protocol error: {m}"),
            Error::Crypto(m) => write!(f, "crypto error: {m}"),
            Error::Http(m) => write!(f, "http error: {m}"),
            Error::Unsupported(m) => write!(f, "unsupported: {m}"),
            Error::Device { code, message } => write!(f, "device error {code}: {message}"),
            Error::Locked { retry_in_secs } => {
                write!(
                    f,
                    "paused for {retry_in_secs}s after an authentication failure (avoids locking the bulb)"
                )
            }
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// Values the device returns in `pake_register`.
pub struct Register {
    pub dev_random: Vec<u8>,
    pub dev_salt: Vec<u8>,
    pub dev_share: Vec<u8>,
    pub iterations: u32,
}

pub struct ShareOut {
    pub user_share: Vec<u8>,
    pub user_confirm: Vec<u8>,
    pub expected_dev_confirm: Vec<u8>,
    pub shared_key: [u8; 32],
}

/// Big-endian integer of any length reduced modulo the group order.
fn scalar_from_be(bytes: &[u8]) -> Scalar {
    let base = Scalar::from(256u64);
    bytes.iter().fold(Scalar::ZERO, |acc, b| {
        acc * base + Scalar::from(u64::from(*b))
    })
}

fn decode_point(sec1: &[u8]) -> Result<ProjectivePoint> {
    let encoded =
        Sec1Point::from_bytes(sec1).map_err(|e| Error::Crypto(format!("bad point: {e}")))?;
    let affine: Option<AffinePoint> = AffinePoint::from_sec1_point(&encoded).into();
    let point = affine
        .map(ProjectivePoint::from)
        .ok_or_else(|| Error::Crypto("point is not on the curve".into()))?;
    // A hostile peer could send the identity element to force a degenerate exchange.
    if point == ProjectivePoint::IDENTITY {
        return Err(Error::Crypto("point at infinity".into()));
    }
    Ok(point)
}

/// Equality check whose running time does not depend on where the inputs differ.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn encode_point(point: &ProjectivePoint) -> Vec<u8> {
    point.to_affine().to_sec1_point(false).as_bytes().to_vec()
}

fn len8le(value: &[u8]) -> Vec<u8> {
    let mut out = (value.len() as u64).to_le_bytes().to_vec();
    out.extend_from_slice(value);
    out
}

/// Minimal big-endian encoding of `w`, kept identical to the reference client
/// (even lengths as-is; odd lengths get a 0x00 prefix when the top bit is set).
fn encode_w(w: &Scalar) -> Vec<u8> {
    let full = w.to_bytes();
    let first = full.iter().position(|b| *b != 0).unwrap_or(full.len() - 1);
    let unsigned = full[first..].to_vec();
    if unsigned.len().is_multiple_of(2) {
        unsigned
    } else if unsigned[0] & 0x80 != 0 {
        let mut out = vec![0u8];
        out.extend(unsigned);
        out
    } else {
        unsigned
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn hmac(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(key).map_err(|e| Error::Crypto(e.to_string()))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// HKDF with an all-zero salt of the digest length (as the device does).
fn hkdf_labeled(label: &str, ikm: &[u8], len: usize) -> Result<Vec<u8>> {
    let salt = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(&salt), ikm);
    let mut out = vec![0u8; len];
    hk.expand(label.as_bytes(), &mut out)
        .map_err(|e| Error::Crypto(e.to_string()))?;
    Ok(out)
}

/// Client side of SPAKE2+ (RFC 9383 style, device-specific transcript).
/// `x` is the client's ephemeral secret scalar.
pub fn build_share(
    credentials: &str,
    user_random: &[u8],
    reg: &Register,
    x: Scalar,
) -> Result<ShareOut> {
    if reg.iterations == 0 {
        return Err(Error::Protocol("iterations must be > 0".into()));
    }
    let m_point = decode_point(&hex::decode(M_COMPRESSED).expect("const"))?;
    let n_point = decode_point(&hex::decode(N_COMPRESSED).expect("const"))?;

    // PBKDF2 yields two 40-byte integers: w and h.
    let mut derived = [0u8; 80];
    pbkdf2::pbkdf2_hmac::<Sha256>(
        credentials.as_bytes(),
        &reg.dev_salt,
        reg.iterations,
        &mut derived,
    );
    let w = scalar_from_be(&derived[..40]);
    let h = scalar_from_be(&derived[40..]);

    let l_point = ProjectivePoint::GENERATOR * x + m_point * w;
    let r_point = decode_point(&reg.dev_share)?;
    let r_prime = r_point - n_point * w;
    let z_point = r_prime * x;
    let v_point = r_prime * h;

    let l_enc = encode_point(&l_point);
    let r_enc = encode_point(&r_point);
    let z_enc = encode_point(&z_point);
    let v_enc = encode_point(&v_point);
    let m_enc = encode_point(&m_point);
    let n_enc = encode_point(&n_point);

    let mut context = PAKE_CONTEXT_TAG.to_vec();
    context.extend_from_slice(user_random);
    context.extend_from_slice(&reg.dev_random);
    let context_hash = sha256(&context);

    let mut transcript = Vec::new();
    for part in [
        context_hash.as_slice(),
        b"",
        b"",
        &m_enc,
        &n_enc,
        &l_enc,
        &r_enc,
        &z_enc,
        &v_enc,
        &encode_w(&w),
    ] {
        transcript.extend(len8le(part));
    }
    let transcript_hash = sha256(&transcript);

    let confirmation = hkdf_labeled("ConfirmationKeys", &transcript_hash, 64)?;
    let (key_a, key_b) = confirmation.split_at(32);
    let shared_key: [u8; 32] = hkdf_labeled("SharedKey", &transcript_hash, 32)?
        .try_into()
        .map_err(|_| Error::Crypto("shared key length".into()))?;

    Ok(ShareOut {
        user_share: l_enc.clone(),
        user_confirm: hmac(key_a, &r_enc)?,
        expected_dev_confirm: hmac(key_b, &l_enc)?,
        shared_key,
    })
}

/// A fresh random non-zero scalar (48 random bytes reduced mod the order).
pub fn random_scalar() -> Scalar {
    loop {
        let bytes: [u8; 48] = rand::random();
        let s = scalar_from_be(&bytes);
        if s != Scalar::ZERO {
            return s;
        }
    }
}

pub fn scalar_from_hex(hex_str: &str) -> Result<Scalar> {
    let padded = if hex_str.len() % 2 == 1 {
        format!("0{hex_str}")
    } else {
        hex_str.to_string()
    };
    let bytes = hex::decode(padded).map_err(|e| Error::Crypto(e.to_string()))?;
    Ok(scalar_from_be(&bytes))
}

/// AES-128-CCM session: 16-byte key, 12-byte base nonce whose last 4 bytes
/// are replaced by the big-endian sequence number.
pub struct Session {
    key: [u8; 16],
    base_nonce: [u8; 12],
}

impl Drop for Session {
    fn drop(&mut self) {
        self.key.zeroize();
        self.base_nonce.zeroize();
    }
}

impl Session {
    pub fn from_shared_key(shared_key: &[u8]) -> Result<Self> {
        let derive = |salt: &[u8], info: &[u8], out: &mut [u8]| {
            Hkdf::<Sha256>::new(Some(salt), shared_key)
                .expand(info, out)
                .map_err(|e| Error::Crypto(e.to_string()))
        };
        let mut key = [0u8; 16];
        let mut base_nonce = [0u8; 12];
        derive(
            b"tp-kdf-salt-aes128-key",
            b"tp-kdf-info-aes128-key",
            &mut key,
        )?;
        derive(
            b"tp-kdf-salt-aes128-iv",
            b"tp-kdf-info-aes128-iv",
            &mut base_nonce,
        )?;
        Ok(Self { key, base_nonce })
    }

    pub fn key_and_nonce(&self) -> ([u8; 16], [u8; 12]) {
        (self.key, self.base_nonce)
    }

    fn nonce(&self, seq: u32) -> [u8; 12] {
        let mut n = self.base_nonce;
        n[8..].copy_from_slice(&seq.to_be_bytes());
        n
    }

    fn cipher(&self) -> Aes128Ccm {
        Aes128Ccm::new((&self.key).into())
    }

    /// Returns ciphertext || 16-byte tag.
    pub fn seal(&self, seq: u32, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.cipher()
            .encrypt(
                (&self.nonce(seq)).into(),
                Payload {
                    msg: plaintext,
                    aad: b"",
                },
            )
            .map_err(|_| Error::Crypto("encryption failed".into()))
    }

    pub fn open(&self, seq: u32, ciphertext_and_tag: &[u8]) -> Result<Vec<u8>> {
        self.cipher()
            .decrypt(
                (&self.nonce(seq)).into(),
                Payload {
                    msg: ciphertext_and_tag,
                    aad: b"",
                },
            )
            .map_err(|_| Error::Crypto("decryption failed (bad tag)".into()))
    }

    /// Wire format of a request: 4-byte BE sequence + ciphertext + tag.
    pub fn encrypt_request(&self, seq: u32, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut out = seq.to_be_bytes().to_vec();
        out.extend(self.seal(seq, plaintext)?);
        Ok(out)
    }

    /// Responses carry their own sequence number in the first 4 bytes.
    pub fn decrypt_response(&self, payload: &[u8]) -> Result<Vec<u8>> {
        if payload.len() < 4 + 16 {
            return Err(Error::Protocol("response too short".into()));
        }
        let seq = u32::from_be_bytes(payload[..4].try_into().expect("4 bytes"));
        self.open(seq, &payload[4..])
    }
}
