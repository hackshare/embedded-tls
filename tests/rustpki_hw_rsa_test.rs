#![cfg(feature = "hw-rsa")]
//! Integration test for the `hw-rsa` feature.
//!
//! Provides software RSA implementations as the extern "Rust" callback bodies,
//! verifying that the hw-rsa dispatch path works correctly through a real TLS
//! handshake against a local RSA-based TLS server.

use embedded_io_adapters::tokio_1::FromTokio;
use embedded_tls::pki::CertVerifier;
use embedded_tls::{Aes128GcmSha256, CryptoProvider, SignatureScheme, TlsError, TlsVerifier};
use rand_core::OsRng;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::signature::Verifier;
use signature::SignerMut;
use std::net::SocketAddr;
use std::sync::Once;
use std::time::SystemTime;

mod tlsserver;

static LOG_INIT: Once = Once::new();
static INIT: Once = Once::new();
static mut ADDR: Option<SocketAddr> = None;

// --- hw-rsa callback implementations using software RSA ---

/// PKCS#1 v1.5 SHA-256 verification callback.
#[unsafe(no_mangle)]
fn embedded_tls_verify_rsa_pkcs1v15_sha256(
    pk: *const u8,
    pk_len: usize,
    sig: *const u8,
    sig_len: usize,
    msg: *const u8,
    msg_len: usize,
) -> bool {
    let pk = unsafe { core::slice::from_raw_parts(pk, pk_len) };
    let sig = unsafe { core::slice::from_raw_parts(sig, sig_len) };
    let msg = unsafe { core::slice::from_raw_parts(msg, msg_len) };

    let Ok(public_key) = rsa::RsaPublicKey::from_pkcs1_der(pk) else {
        return false;
    };
    let verifying_key = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(public_key);
    let Ok(signature) = rsa::pkcs1v15::Signature::try_from(sig) else {
        return false;
    };
    verifying_key.verify(msg, &signature).is_ok()
}

/// PKCS#1 v1.5 SHA-384 verification callback.
#[unsafe(no_mangle)]
fn embedded_tls_verify_rsa_pkcs1v15_sha384(
    pk: *const u8,
    pk_len: usize,
    sig: *const u8,
    sig_len: usize,
    msg: *const u8,
    msg_len: usize,
) -> bool {
    let pk = unsafe { core::slice::from_raw_parts(pk, pk_len) };
    let sig = unsafe { core::slice::from_raw_parts(sig, sig_len) };
    let msg = unsafe { core::slice::from_raw_parts(msg, msg_len) };

    let Ok(public_key) = rsa::RsaPublicKey::from_pkcs1_der(pk) else {
        return false;
    };
    let verifying_key = rsa::pkcs1v15::VerifyingKey::<sha2::Sha384>::new(public_key);
    let Ok(signature) = rsa::pkcs1v15::Signature::try_from(sig) else {
        return false;
    };
    verifying_key.verify(msg, &signature).is_ok()
}

/// PKCS#1 v1.5 SHA-512 verification callback.
#[unsafe(no_mangle)]
fn embedded_tls_verify_rsa_pkcs1v15_sha512(
    pk: *const u8,
    pk_len: usize,
    sig: *const u8,
    sig_len: usize,
    msg: *const u8,
    msg_len: usize,
) -> bool {
    let pk = unsafe { core::slice::from_raw_parts(pk, pk_len) };
    let sig = unsafe { core::slice::from_raw_parts(sig, sig_len) };
    let msg = unsafe { core::slice::from_raw_parts(msg, msg_len) };

    let Ok(public_key) = rsa::RsaPublicKey::from_pkcs1_der(pk) else {
        return false;
    };
    let verifying_key = rsa::pkcs1v15::VerifyingKey::<sha2::Sha512>::new(public_key);
    let Ok(signature) = rsa::pkcs1v15::Signature::try_from(sig) else {
        return false;
    };
    verifying_key.verify(msg, &signature).is_ok()
}

/// RSA-PSS SHA-256 verification callback.
#[unsafe(no_mangle)]
fn embedded_tls_verify_rsa_pss_sha256(
    pk: *const u8,
    pk_len: usize,
    sig: *const u8,
    sig_len: usize,
    msg: *const u8,
    msg_len: usize,
) -> bool {
    let pk = unsafe { core::slice::from_raw_parts(pk, pk_len) };
    let sig = unsafe { core::slice::from_raw_parts(sig, sig_len) };
    let msg = unsafe { core::slice::from_raw_parts(msg, msg_len) };

    let Ok(public_key) = rsa::RsaPublicKey::from_pkcs1_der(pk) else {
        return false;
    };
    let verifying_key = rsa::pss::VerifyingKey::<sha2::Sha256>::from(public_key);
    let Ok(signature) = rsa::pss::Signature::try_from(sig) else {
        return false;
    };
    verifying_key.verify(msg, &signature).is_ok()
}

/// RSA-PSS SHA-384 verification callback.
#[unsafe(no_mangle)]
fn embedded_tls_verify_rsa_pss_sha384(
    pk: *const u8,
    pk_len: usize,
    sig: *const u8,
    sig_len: usize,
    msg: *const u8,
    msg_len: usize,
) -> bool {
    let pk = unsafe { core::slice::from_raw_parts(pk, pk_len) };
    let sig = unsafe { core::slice::from_raw_parts(sig, sig_len) };
    let msg = unsafe { core::slice::from_raw_parts(msg, msg_len) };

    let Ok(public_key) = rsa::RsaPublicKey::from_pkcs1_der(pk) else {
        return false;
    };
    let verifying_key = rsa::pss::VerifyingKey::<sha2::Sha384>::from(public_key);
    let Ok(signature) = rsa::pss::Signature::try_from(sig) else {
        return false;
    };
    verifying_key.verify(msg, &signature).is_ok()
}

/// RSA-PSS SHA-512 verification callback.
#[unsafe(no_mangle)]
fn embedded_tls_verify_rsa_pss_sha512(
    pk: *const u8,
    pk_len: usize,
    sig: *const u8,
    sig_len: usize,
    msg: *const u8,
    msg_len: usize,
) -> bool {
    let pk = unsafe { core::slice::from_raw_parts(pk, pk_len) };
    let sig = unsafe { core::slice::from_raw_parts(sig, sig_len) };
    let msg = unsafe { core::slice::from_raw_parts(msg, msg_len) };

    let Ok(public_key) = rsa::RsaPublicKey::from_pkcs1_der(pk) else {
        return false;
    };
    let verifying_key = rsa::pss::VerifyingKey::<sha2::Sha512>::from(public_key);
    let Ok(signature) = rsa::pss::Signature::try_from(sig) else {
        return false;
    };
    verifying_key.verify(msg, &signature).is_ok()
}

// --- Provider for hw-rsa (no client cert signing, server-only validation) ---

#[derive(Default)]
struct HwRsaProvider {
    rng: rand::rngs::OsRng,
    verifier: CertVerifier<Aes128GcmSha256, SystemTime, 4096>,
}

impl CryptoProvider for HwRsaProvider {
    type CipherSuite = Aes128GcmSha256;
    type Signature = p256::ecdsa::DerSignature;

    fn rng(&mut self) -> impl embedded_tls::CryptoRngCore {
        &mut self.rng
    }

    fn verifier(&mut self) -> Result<&mut impl TlsVerifier<Aes128GcmSha256>, TlsError> {
        Ok(&mut self.verifier)
    }

    fn signer(
        &mut self,
        _key_der: &[u8],
    ) -> Result<(impl SignerMut<Self::Signature>, SignatureScheme), TlsError> {
        // hw-rsa tests don't use client certs, so this is unreachable.
        // Provide a dummy that satisfies the type system.
        Err::<(DummySigner, SignatureScheme), _>(TlsError::Unimplemented)
    }
}

struct DummySigner;
impl SignerMut<p256::ecdsa::DerSignature> for DummySigner {
    fn try_sign(
        &mut self,
        _msg: &[u8],
    ) -> Result<p256::ecdsa::DerSignature, p256::ecdsa::Error> {
        unreachable!()
    }
}

fn init_log() {
    LOG_INIT.call_once(|| {
        env_logger::init();
    });
}

fn setup() -> SocketAddr {
    use mio::net::TcpListener;
    init_log();
    INIT.call_once(|| {
        let addr: SocketAddr = "127.0.0.1:12347".parse().unwrap();

        let listener = TcpListener::bind(addr).expect("cannot listen on port");
        let addr = listener
            .local_addr()
            .expect("error retrieving socket address");

        std::thread::spawn(move || {
            use tlsserver::*;

            let versions = &[&rustls::version::TLS13];

            let test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");

            let certs = load_certs(&test_dir.join("data").join("rsa-server-cert.pem"));
            let privkey = load_private_key(&test_dir.join("data").join("rsa-server-key.pem"));

            let config = rustls::ServerConfig::builder()
                .with_cipher_suites(rustls::ALL_CIPHER_SUITES)
                .with_kx_groups(&rustls::ALL_KX_GROUPS)
                .with_protocol_versions(versions)
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(certs, privkey)
                .unwrap();

            run_with_config(listener, config);
        });
        #[allow(static_mut_refs)]
        unsafe {
            ADDR.replace(addr)
        };
    });
    unsafe { ADDR.unwrap() }
}

/// Test that hw-rsa callbacks are correctly dispatched during TLS handshake
/// with an RSA-based server certificate chain.
#[tokio::test]
async fn test_hw_rsa_certificate_validation() {
    use embedded_tls::*;

    let addr = setup();
    let pem = include_str!("data/rsa-ca-cert.pem");
    let der = pem_parser::pem_to_der(pem);

    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("error connecting to server");

    let mut read_record_buffer = [0; 16640];
    let mut write_record_buffer = [0; 16640];

    let config = TlsConfig::new()
        .with_ca(Certificate::X509(&der[..]))
        .with_server_name("localhost");

    let mut tls = TlsConnection::new(
        FromTokio::new(stream),
        &mut read_record_buffer,
        &mut write_record_buffer,
    );

    let open_fut = tls.open(TlsContext::new(
        &config,
        HwRsaProvider {
            rng: OsRng,
            verifier: CertVerifier::new(),
        },
    ));

    open_fut.await.expect("error establishing TLS connection");

    tls.close()
        .await
        .map_err(|(_, e)| e)
        .expect("error closing session");
}
