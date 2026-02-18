use crate::TlsError;
use crate::config::{Certificate, TlsCipherSuite, TlsClock, TlsVerifier};
#[cfg(feature = "p384")]
use crate::der_certificate::ECDSA_SHA384;
#[cfg(feature = "ed25519")]
use crate::der_certificate::ED25519;
use crate::der_certificate::{DecodedCertificate, ECDSA_SHA256, Time};
#[cfg(any(feature = "rsa", feature = "hw-rsa"))]
use crate::der_certificate::{RSA_PKCS1_SHA1, RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512};
use crate::extensions::extension_data::signature_algorithms::SignatureScheme;
use crate::handshake::{
    certificate::{
        Certificate as OwnedCertificate, CertificateEntryRef, CertificateRef as ServerCertificate,
    },
    certificate_verify::CertificateVerifyRef,
};
use crate::parse_buffer::ParseError;
use const_oid::ObjectIdentifier;
use core::marker::PhantomData;
use der::Decode;
use digest::Digest;
use heapless::{String, Vec};

const HOSTNAME_MAXLEN: usize = 64;
const COMMON_NAME_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");

/// Result of hostname verification against a certificate.
struct HostnameResult {
    common_name: Option<heapless::String<HOSTNAME_MAXLEN>>,
    /// None = no SANs found, Some(true) = SAN matched, Some(false) = SANs present but no match.
    san_match: Option<bool>,
}

impl HostnameResult {
    /// Check if a hostname matches this certificate's identity.
    ///
    /// Per RFC 6125: if SANs are present, only SANs are checked (CN is ignored).
    fn matches_hostname(&self, hostname: &str) -> bool {
        match self.san_match {
            Some(result) => result,
            None => self
                .common_name
                .as_ref()
                .map(|cn| hostname_matches(cn.as_str(), hostname))
                .unwrap_or(false),
        }
    }
}

/// Check if a certificate name (possibly wildcard) matches a hostname.
///
/// Case-insensitive per RFC 6125. Supports `*.example.com` matching
/// `foo.example.com` but not `example.com` or `foo.bar.example.com`
/// (single-level wildcard only, per RFC 6125 §6.4.3).
fn hostname_matches(pattern: &str, hostname: &str) -> bool {
    if pattern.eq_ignore_ascii_case(hostname) {
        return true;
    }
    // Wildcard: *.example.com
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // Hostname must be longer than suffix + 1 (at least "x." + suffix)
        if hostname.len() > suffix.len() + 1 {
            let hostname_suffix = &hostname[hostname.len() - suffix.len()..];
            let hostname_prefix = &hostname[..hostname.len() - suffix.len()];
            // Suffix must match case-insensitively
            if hostname_suffix.eq_ignore_ascii_case(suffix)
                // Prefix must be "label." (ends with dot, single label)
                && hostname_prefix.ends_with('.')
                && !hostname_prefix[..hostname_prefix.len() - 1].contains('.')
            {
                return true;
            }
        }
    }
    false
}

pub struct CertificateChain<'a> {
    prev: Option<&'a CertificateEntryRef<'a>>,
    chain: &'a ServerCertificate<'a>,
    idx: isize,
}

impl<'a> CertificateChain<'a> {
    pub fn new(ca: &'a CertificateEntryRef, chain: &'a ServerCertificate<'a>) -> Self {
        Self {
            prev: Some(ca),
            chain,
            idx: chain.entries.len() as isize - 1,
        }
    }
}

impl<'a> Iterator for CertificateChain<'a> {
    type Item = (&'a CertificateEntryRef<'a>, &'a CertificateEntryRef<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx < 0 {
            return None;
        }

        let cur = &self.chain.entries[self.idx as usize];
        let out = (self.prev.unwrap(), cur);

        self.prev = Some(cur);
        self.idx -= 1;

        Some(out)
    }
}

pub struct CertVerifier<CipherSuite, Clock, const CERT_SIZE: usize>
where
    Clock: TlsClock,
    CipherSuite: TlsCipherSuite,
{
    host: Option<heapless::String<64>>,
    certificate_transcript: Option<CipherSuite::Hash>,
    certificate: Option<OwnedCertificate<CERT_SIZE>>,
    _clock: PhantomData<Clock>,
}

impl<Cs, C, const CERT_SIZE: usize> Default for CertVerifier<Cs, C, CERT_SIZE>
where
    C: TlsClock,
    Cs: TlsCipherSuite,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<CipherSuite, Clock, const CERT_SIZE: usize> CertVerifier<CipherSuite, Clock, CERT_SIZE>
where
    Clock: TlsClock,
    CipherSuite: TlsCipherSuite,
{
    #[must_use]
    pub fn new() -> Self {
        Self {
            host: None,
            certificate_transcript: None,
            certificate: None,
            _clock: PhantomData,
        }
    }
}

impl<CipherSuite, Clock, const CERT_SIZE: usize> TlsVerifier<CipherSuite>
    for CertVerifier<CipherSuite, Clock, CERT_SIZE>
where
    CipherSuite: TlsCipherSuite,
    Clock: TlsClock,
{
    fn set_hostname_verification(&mut self, hostname: &str) -> Result<(), TlsError> {
        self.host.replace(
            heapless::String::try_from(hostname).map_err(|_| TlsError::InsufficientSpace)?,
        );
        Ok(())
    }

    fn verify_certificate(
        &mut self,
        transcript: &CipherSuite::Hash,
        ca: &Option<Certificate>,
        cert: ServerCertificate,
    ) -> Result<(), TlsError> {
        let ca = if let Some(ca) = ca {
            ca
        } else {
            error!("Verifying a certificate chain without ca is not implemented");
            return Err(TlsError::Unimplemented);
        };

        let mut result = HostnameResult {
            common_name: None,
            san_match: None,
        };
        let hostname_ref = self.host.as_deref();
        for (p, q) in CertificateChain::new(&ca.into(), &cert) {
            result = verify_certificate(p, q, Clock::now(), hostname_ref)?;
        }
        if let Some(ref hostname) = self.host {
            if !result.matches_hostname(hostname.as_str()) {
                error!(
                    "Hostname ({:?}) does not match certificate (CN={:?}, SAN match={:?})",
                    self.host, result.common_name, result.san_match
                );
                return Err(TlsError::InvalidCertificate);
            }
        }

        self.certificate.replace(cert.try_into()?);
        self.certificate_transcript.replace(transcript.clone());
        Ok(())
    }

    fn verify_signature(&mut self, verify: CertificateVerifyRef) -> Result<(), TlsError> {
        let handshake_hash = unwrap!(self.certificate_transcript.take());
        let ctx_str = b"TLS 1.3, server CertificateVerify\x00";
        let mut msg: Vec<u8, 146> = Vec::new();
        msg.resize(64, 0x20).map_err(|_| TlsError::EncodeError)?;
        msg.extend_from_slice(ctx_str)
            .map_err(|_| TlsError::EncodeError)?;
        msg.extend_from_slice(&handshake_hash.finalize())
            .map_err(|_| TlsError::EncodeError)?;

        let certificate = unwrap!(self.certificate.as_ref()).try_into()?;
        verify_signature(&msg[..], &certificate, &verify)?;
        Ok(())
    }
}

fn verify_signature(
    message: &[u8],
    certificate: &ServerCertificate,
    verify: &CertificateVerifyRef,
) -> Result<(), TlsError> {
    let verified;

    let certificate =
        if let Some(CertificateEntryRef::X509(certificate)) = certificate.entries.first() {
            certificate
        } else {
            return Err(TlsError::DecodeError);
        };

    let certificate =
        DecodedCertificate::from_der(certificate).map_err(|_| TlsError::DecodeError)?;

    let public_key = certificate
        .tbs_certificate
        .subject_public_key_info
        .public_key
        .as_bytes()
        .ok_or(TlsError::DecodeError)?;

    match verify.signature_scheme {
        SignatureScheme::EcdsaSecp256r1Sha256 => {
            use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
            let verifying_key =
                VerifyingKey::from_sec1_bytes(public_key).map_err(|_| TlsError::DecodeError)?;
            let signature =
                Signature::from_der(&verify.signature).map_err(|_| TlsError::DecodeError)?;
            verified = verifying_key.verify(message, &signature).is_ok();
        }
        #[cfg(feature = "p384")]
        SignatureScheme::EcdsaSecp384r1Sha384 => {
            use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier};
            let verifying_key =
                VerifyingKey::from_sec1_bytes(public_key).map_err(|_| TlsError::DecodeError)?;
            let signature =
                Signature::from_der(&verify.signature).map_err(|_| TlsError::DecodeError)?;
            verified = verifying_key.verify(message, &signature).is_ok();
        }
        #[cfg(feature = "ed25519")]
        SignatureScheme::Ed25519 => {
            use ed25519_dalek::{Signature, Verifier, VerifyingKey};
            let verifying_key: VerifyingKey =
                VerifyingKey::from_bytes(public_key.try_into().unwrap())
                    .map_err(|_| TlsError::DecodeError)?;
            let signature =
                Signature::try_from(verify.signature).map_err(|_| TlsError::DecodeError)?;
            verified = verifying_key.verify(message, &signature).is_ok();
        }
        #[cfg(feature = "rsa")]
        SignatureScheme::RsaPssRsaeSha256 => {
            use rsa::{
                RsaPublicKey,
                pkcs1::DecodeRsaPublicKey,
                pss::{Signature, VerifyingKey},
                signature::Verifier,
            };
            use sha2::Sha256;

            let der_pubkey = RsaPublicKey::from_pkcs1_der(public_key).unwrap();
            let verifying_key = VerifyingKey::<Sha256>::from(der_pubkey);

            let signature =
                Signature::try_from(verify.signature).map_err(|_| TlsError::DecodeError)?;
            verified = verifying_key.verify(message, &signature).is_ok();
        }
        #[cfg(feature = "rsa")]
        SignatureScheme::RsaPssRsaeSha384 => {
            use rsa::{
                RsaPublicKey,
                pkcs1::DecodeRsaPublicKey,
                pss::{Signature, VerifyingKey},
                signature::Verifier,
            };
            use sha2::Sha384;

            let der_pubkey =
                RsaPublicKey::from_pkcs1_der(public_key).map_err(|_| TlsError::DecodeError)?;
            let verifying_key = VerifyingKey::<Sha384>::from(der_pubkey);

            let signature =
                Signature::try_from(verify.signature).map_err(|_| TlsError::DecodeError)?;
            verified = verifying_key.verify(message, &signature).is_ok();
        }
        #[cfg(feature = "rsa")]
        SignatureScheme::RsaPssRsaeSha512 => {
            use rsa::{
                RsaPublicKey,
                pkcs1::DecodeRsaPublicKey,
                pss::{Signature, VerifyingKey},
                signature::Verifier,
            };
            use sha2::Sha512;

            let der_pubkey =
                RsaPublicKey::from_pkcs1_der(public_key).map_err(|_| TlsError::DecodeError)?;
            let verifying_key = VerifyingKey::<Sha512>::from(der_pubkey);

            let signature =
                Signature::try_from(verify.signature).map_err(|_| TlsError::DecodeError)?;
            verified = verifying_key.verify(message, &signature).is_ok();
        }
        #[cfg(feature = "hw-rsa")]
        SignatureScheme::RsaPssRsaeSha256 => {
            unsafe extern "Rust" {
                safe fn embedded_tls_verify_rsa_pss_sha256(
                    pk: *const u8, pk_len: usize,
                    sig: *const u8, sig_len: usize,
                    msg: *const u8, msg_len: usize,
                ) -> bool;
            }
            verified = embedded_tls_verify_rsa_pss_sha256(
                public_key.as_ptr(), public_key.len(),
                verify.signature.as_ptr(), verify.signature.len(),
                message.as_ptr(), message.len(),
            );
        }
        #[cfg(feature = "hw-rsa")]
        SignatureScheme::RsaPssRsaeSha384 => {
            unsafe extern "Rust" {
                safe fn embedded_tls_verify_rsa_pss_sha384(
                    pk: *const u8, pk_len: usize,
                    sig: *const u8, sig_len: usize,
                    msg: *const u8, msg_len: usize,
                ) -> bool;
            }
            verified = embedded_tls_verify_rsa_pss_sha384(
                public_key.as_ptr(), public_key.len(),
                verify.signature.as_ptr(), verify.signature.len(),
                message.as_ptr(), message.len(),
            );
        }
        #[cfg(feature = "hw-rsa")]
        SignatureScheme::RsaPssRsaeSha512 => {
            unsafe extern "Rust" {
                safe fn embedded_tls_verify_rsa_pss_sha512(
                    pk: *const u8, pk_len: usize,
                    sig: *const u8, sig_len: usize,
                    msg: *const u8, msg_len: usize,
                ) -> bool;
            }
            verified = embedded_tls_verify_rsa_pss_sha512(
                public_key.as_ptr(), public_key.len(),
                verify.signature.as_ptr(), verify.signature.len(),
                message.as_ptr(), message.len(),
            );
        }
        _ => {
            error!(
                "InvalidSignatureScheme: {:?} Are you missing a feature?",
                verify.signature_scheme
            );
            return Err(TlsError::InvalidSignatureScheme);
        }
    }

    if !verified {
        return Err(TlsError::InvalidSignature);
    }
    Ok(())
}

/// Stream-check hostname against Subject Alternative Name DNS entries.
///
/// Parses extensions DER bytes to find the SAN extension (OID 2.5.29.17),
/// then evaluates each dNSName entry against the hostname during parsing.
/// No allocation — returns early on first match.
///
/// Returns:
/// - `Ok(None)` — no SAN extension found (caller should fall back to CN)
/// - `Ok(Some(true))` — a SAN DNS name matched the hostname
/// - `Ok(Some(false))` — SANs present but none matched
/// - `Err(())` — malformed DER (caller must reject the certificate)
fn san_matches_hostname(extensions_bytes: &[u8], hostname: Option<&str>) -> Result<Option<bool>, ()> {
    // AnyRef::value() gives us the content of the Extensions SEQUENCE (tag+length
    // already stripped). We iterate directly over the Extension entries.
    let mut pos = 0;
    let len = extensions_bytes.len();

    while pos < len {
        let (tag, ext_len, hdr_len) = read_tag_len(extensions_bytes, pos).ok_or(())?;
        if pos + hdr_len + ext_len > len {
            return Err(()); // Malformed: length exceeds buffer
        }
        if tag != 0x30 {
            pos += hdr_len + ext_len;
            continue;
        }
        let ext_start = pos + hdr_len;
        let ext_end = ext_start + ext_len;
        pos = ext_start;

        // Read OID
        let (oid_tag, oid_len, oid_hdr) = read_tag_len(extensions_bytes, pos).ok_or(())?;
        if oid_tag != 0x06 || pos + oid_hdr + oid_len > ext_end {
            pos = ext_end;
            continue;
        }
        let oid_bytes = &extensions_bytes[pos + oid_hdr..pos + oid_hdr + oid_len];
        pos += oid_hdr + oid_len;

        // Check if this is the SAN OID (2.5.29.17 = 55 1d 11)
        if oid_bytes != [0x55, 0x1d, 0x11] {
            pos = ext_end;
            continue;
        }

        // Found SAN extension — skip optional BOOLEAN (critical flag)
        if pos < ext_end {
            let (next_tag, _, _) = read_tag_len(extensions_bytes, pos).ok_or(())?;
            if next_tag == 0x01 {
                let (_, bool_len, bool_hdr) = read_tag_len(extensions_bytes, pos).ok_or(())?;
                if pos + bool_hdr + bool_len > ext_end {
                    return Err(());
                }
                pos += bool_hdr + bool_len;
            }
        }

        // Read OCTET STRING containing the SAN value
        if pos >= ext_end {
            return Err(());
        }
        let (oct_tag, oct_len, oct_hdr) = read_tag_len(extensions_bytes, pos).ok_or(())?;
        if oct_tag != 0x04 || pos + oct_hdr + oct_len > ext_end {
            return Err(());
        }
        let san_start = pos + oct_hdr;
        let san_end = san_start + oct_len;
        if san_end > len {
            return Err(()); // Malformed
        }
        let san_value = &extensions_bytes[san_start..san_end];

        // SAN value is a SEQUENCE OF GeneralName
        let mut san_pos = 0;
        let (san_seq_tag, san_seq_len, san_seq_hdr) = read_tag_len(san_value, san_pos).ok_or(())?;
        if san_seq_tag != 0x30 || san_pos + san_seq_hdr + san_seq_len > san_value.len() {
            return Err(());
        }
        san_pos += san_seq_hdr;
        let san_seq_end = san_pos + san_seq_len;

        // Stream through GeneralName entries
        while san_pos < san_seq_end {
            let (gn_tag, gn_len, gn_hdr) = read_tag_len(san_value, san_pos).ok_or(())?;
            if san_pos + gn_hdr + gn_len > san_seq_end {
                return Err(()); // Malformed
            }
            let gn_data = &san_value[san_pos + gn_hdr..san_pos + gn_hdr + gn_len];
            san_pos += gn_hdr + gn_len;

            // Context tag [2] = dNSName (implicit IA5String)
            if gn_tag == 0x82 {
                if let Ok(name_str) = core::str::from_utf8(gn_data) {
                    // Reject null bytes (null-byte injection defense)
                    if name_str.contains('\0') {
                        continue;
                    }
                    if let Some(host) = hostname {
                        if hostname_matches(name_str, host) {
                            return Ok(Some(true)); // Match — return early
                        }
                    }
                }
            }
        }

        return Ok(Some(false)); // SANs found but none matched
    }

    Ok(None) // No SAN extension found
}

/// Read a DER tag and length at the given position.
/// Returns (tag, content_length, header_length) or None.
fn read_tag_len(data: &[u8], pos: usize) -> Option<(u8, usize, usize)> {
    if pos >= data.len() {
        return None;
    }
    let tag = data[pos];
    if pos + 1 >= data.len() {
        return None;
    }
    let first = data[pos + 1];
    if first < 0x80 {
        // Short form: length is the byte itself
        Some((tag, first as usize, 2))
    } else if first == 0x81 {
        // Long form: 1 byte length
        if pos + 2 >= data.len() {
            return None;
        }
        Some((tag, data[pos + 2] as usize, 3))
    } else if first == 0x82 {
        // Long form: 2 byte length
        if pos + 3 >= data.len() {
            return None;
        }
        let len = ((data[pos + 2] as usize) << 8) | (data[pos + 3] as usize);
        Some((tag, len, 4))
    } else {
        // Unsupported length encoding
        None
    }
}

fn get_certificate_tlv_bytes<'a>(input: &[u8]) -> der::Result<&[u8]> {
    use der::{Decode, Reader, SliceReader};

    let mut reader = SliceReader::new(input)?;
    let top_header = der::Header::decode(&mut reader)?;
    top_header.tag().assert_eq(der::Tag::Sequence)?;

    let header = der::Header::peek(&mut reader)?;
    header.tag().assert_eq(der::Tag::Sequence)?;

    // Should we read the remaining two fields and call reader.finish() just be certain here?
    reader.tlv_bytes()
}

fn get_cert_time(time: Time) -> u64 {
    match time {
        Time::UtcTime(utc_time) => utc_time.to_unix_duration().as_secs(),
        Time::GeneralTime(generalized_time) => generalized_time.to_unix_duration().as_secs(),
    }
}

fn verify_certificate(
    verifier: &CertificateEntryRef,
    certificate: &CertificateEntryRef,
    now: Option<u64>,
    hostname: Option<&str>,
) -> Result<HostnameResult, TlsError> {
    let mut verified = false;
    let mut common_name = None;
    let mut san_match: Option<bool> = None;

    let ca_certificate = if let CertificateEntryRef::X509(verifier) = verifier {
        DecodedCertificate::from_der(verifier).map_err(|_| TlsError::DecodeError)?
    } else {
        return Err(TlsError::DecodeError);
    };

    if let CertificateEntryRef::X509(certificate) = certificate {
        let parsed_certificate =
            DecodedCertificate::from_der(certificate).map_err(|_| TlsError::DecodeError)?;

        let ca_public_key = ca_certificate
            .tbs_certificate
            .subject_public_key_info
            .public_key
            .as_bytes()
            .ok_or(TlsError::DecodeError)?;

        for elems in parsed_certificate.tbs_certificate.subject.iter() {
            let attrs = elems
                .get(0)
                .ok_or(TlsError::ParseError(ParseError::InvalidData))?;
            if attrs.oid == COMMON_NAME_OID {
                let mut v: Vec<u8, HOSTNAME_MAXLEN> = Vec::new();
                v.extend_from_slice(attrs.value.value())
                    .map_err(|_| TlsError::ParseError(ParseError::InvalidData))?;
                common_name = String::from_utf8(v).ok();
                debug!("CommonName: {:?}", common_name);
            }
        }

        // Stream-check Subject Alternative Names against hostname
        if let Some(extensions_any) = &parsed_certificate.tbs_certificate.extensions {
            san_match = san_matches_hostname(extensions_any.value(), hostname)
                .map_err(|_| TlsError::DecodeError)?;
        }

        if let Some(now) = now {
            let not_before = get_cert_time(parsed_certificate.tbs_certificate.validity.not_before);
            let not_after = get_cert_time(parsed_certificate.tbs_certificate.validity.not_after);
            if not_before > now || not_after < now {
                debug!("Cert time invalid: now={} not_before={} not_after={}", now, not_before, not_after);
                return Err(TlsError::InvalidCertificate);
            }
            debug!("Epoch is {} and certificate is valid!", now)
        }

        let certificate_data =
            get_certificate_tlv_bytes(certificate).map_err(|_| TlsError::DecodeError)?;

        match parsed_certificate.signature_algorithm {
            ECDSA_SHA256 => {
                use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
                let verifying_key = VerifyingKey::from_sec1_bytes(ca_public_key)
                    .map_err(|_| TlsError::DecodeError)?;

                let signature = Signature::from_der(
                    parsed_certificate
                        .signature
                        .as_bytes()
                        .ok_or(TlsError::ParseError(ParseError::InvalidData))?,
                )
                .map_err(|_| TlsError::ParseError(ParseError::InvalidData))?;

                verified = verifying_key.verify(&certificate_data, &signature).is_ok();
            }
            #[cfg(feature = "p384")]
            ECDSA_SHA384 => {
                use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier};
                let verifying_key = VerifyingKey::from_sec1_bytes(ca_public_key)
                    .map_err(|_| TlsError::DecodeError)?;

                let signature = Signature::from_der(
                    parsed_certificate
                        .signature
                        .as_bytes()
                        .ok_or(TlsError::ParseError(ParseError::InvalidData))?,
                )
                .map_err(|_| TlsError::ParseError(ParseError::InvalidData))?;

                verified = verifying_key.verify(&certificate_data, &signature).is_ok();
            }
            #[cfg(feature = "ed25519")]
            ED25519 => {
                use ed25519_dalek::{Signature, Verifier, VerifyingKey};
                let verifying_key: VerifyingKey =
                    VerifyingKey::from_bytes(ca_public_key.try_into().unwrap())
                        .map_err(|_| TlsError::DecodeError)?;

                let signature = Signature::try_from(
                    parsed_certificate
                        .signature
                        .as_bytes()
                        .ok_or(TlsError::ParseError(ParseError::InvalidData))?,
                )
                .map_err(|_| TlsError::ParseError(ParseError::InvalidData))?;

                verified = verifying_key.verify(certificate_data, &signature).is_ok();
            }
            #[cfg(feature = "rsa")]
            a if a == RSA_PKCS1_SHA256 => {
                use rsa::{
                    pkcs1::DecodeRsaPublicKey,
                    pkcs1v15::{Signature, VerifyingKey},
                    signature::Verifier,
                };
                use sha2::Sha256;

                let verifying_key =
                    VerifyingKey::<Sha256>::from_pkcs1_der(ca_public_key).map_err(|e| {
                        error!("VerifyingKey: {}", e);
                        TlsError::DecodeError
                    })?;

                let signature = Signature::try_from(
                    parsed_certificate
                        .signature
                        .as_bytes()
                        .ok_or(TlsError::ParseError(ParseError::InvalidData))?,
                )
                .map_err(|e| {
                    error!("Signature: {}", e);
                    TlsError::ParseError(ParseError::InvalidData)
                })?;

                verified = verifying_key.verify(certificate_data, &signature).is_ok();
            }
            #[cfg(feature = "rsa")]
            a if a == RSA_PKCS1_SHA384 => {
                use rsa::{
                    pkcs1::DecodeRsaPublicKey,
                    pkcs1v15::{Signature, VerifyingKey},
                    signature::Verifier,
                };
                use sha2::Sha384;

                let verifying_key = VerifyingKey::<Sha384>::from_pkcs1_der(ca_public_key)
                    .map_err(|_| TlsError::DecodeError)?;

                let signature = Signature::try_from(
                    parsed_certificate
                        .signature
                        .as_bytes()
                        .ok_or(TlsError::ParseError(ParseError::InvalidData))?,
                )
                .map_err(|_| TlsError::ParseError(ParseError::InvalidData))?;

                verified = verifying_key.verify(certificate_data, &signature).is_ok();
            }
            #[cfg(feature = "rsa")]
            a if a == RSA_PKCS1_SHA512 => {
                use rsa::{
                    pkcs1::DecodeRsaPublicKey,
                    pkcs1v15::{Signature, VerifyingKey},
                    signature::Verifier,
                };
                use sha2::Sha512;

                let verifying_key = VerifyingKey::<Sha512>::from_pkcs1_der(ca_public_key)
                    .map_err(|_| TlsError::DecodeError)?;

                let signature = Signature::try_from(
                    parsed_certificate
                        .signature
                        .as_bytes()
                        .ok_or(TlsError::ParseError(ParseError::InvalidData))?,
                )
                .map_err(|_| TlsError::ParseError(ParseError::InvalidData))?;

                verified = verifying_key.verify(certificate_data, &signature).is_ok();
            }
            #[cfg(feature = "hw-rsa")]
            a if a == RSA_PKCS1_SHA256 => {
                unsafe extern "Rust" {
                    safe fn embedded_tls_verify_rsa_pkcs1v15_sha256(
                        pk: *const u8, pk_len: usize,
                        sig: *const u8, sig_len: usize,
                        msg: *const u8, msg_len: usize,
                    ) -> bool;
                }
                let sig_bytes = parsed_certificate
                    .signature
                    .as_bytes()
                    .ok_or(TlsError::ParseError(ParseError::InvalidData))?;
                verified = embedded_tls_verify_rsa_pkcs1v15_sha256(
                    ca_public_key.as_ptr(), ca_public_key.len(),
                    sig_bytes.as_ptr(), sig_bytes.len(),
                    certificate_data.as_ptr(), certificate_data.len(),
                );
            }
            #[cfg(feature = "hw-rsa")]
            a if a == RSA_PKCS1_SHA384 => {
                unsafe extern "Rust" {
                    safe fn embedded_tls_verify_rsa_pkcs1v15_sha384(
                        pk: *const u8, pk_len: usize,
                        sig: *const u8, sig_len: usize,
                        msg: *const u8, msg_len: usize,
                    ) -> bool;
                }
                let sig_bytes = parsed_certificate
                    .signature
                    .as_bytes()
                    .ok_or(TlsError::ParseError(ParseError::InvalidData))?;
                verified = embedded_tls_verify_rsa_pkcs1v15_sha384(
                    ca_public_key.as_ptr(), ca_public_key.len(),
                    sig_bytes.as_ptr(), sig_bytes.len(),
                    certificate_data.as_ptr(), certificate_data.len(),
                );
            }
            #[cfg(feature = "hw-rsa")]
            a if a == RSA_PKCS1_SHA512 => {
                unsafe extern "Rust" {
                    safe fn embedded_tls_verify_rsa_pkcs1v15_sha512(
                        pk: *const u8, pk_len: usize,
                        sig: *const u8, sig_len: usize,
                        msg: *const u8, msg_len: usize,
                    ) -> bool;
                }
                let sig_bytes = parsed_certificate
                    .signature
                    .as_bytes()
                    .ok_or(TlsError::ParseError(ParseError::InvalidData))?;
                verified = embedded_tls_verify_rsa_pkcs1v15_sha512(
                    ca_public_key.as_ptr(), ca_public_key.len(),
                    sig_bytes.as_ptr(), sig_bytes.len(),
                    certificate_data.as_ptr(), certificate_data.len(),
                );
            }
            #[cfg(feature = "hw-rsa")]
            a if a == RSA_PKCS1_SHA1 => {
                unsafe extern "Rust" {
                    safe fn embedded_tls_verify_rsa_pkcs1v15_sha1(
                        pk: *const u8, pk_len: usize,
                        sig: *const u8, sig_len: usize,
                        msg: *const u8, msg_len: usize,
                    ) -> bool;
                }
                let sig_bytes = parsed_certificate
                    .signature
                    .as_bytes()
                    .ok_or(TlsError::ParseError(ParseError::InvalidData))?;
                verified = embedded_tls_verify_rsa_pkcs1v15_sha1(
                    ca_public_key.as_ptr(), ca_public_key.len(),
                    sig_bytes.as_ptr(), sig_bytes.len(),
                    certificate_data.as_ptr(), certificate_data.len(),
                );
            }
            _ => {
                error!(
                    "Unsupported signature alg: {:?}",
                    parsed_certificate.signature_algorithm
                );
                return Err(TlsError::InvalidSignatureScheme);
            }
        }
    }

    if !verified {
        debug!("Cert signature verification failed: cn={:?}", common_name);
        return Err(TlsError::InvalidCertificate);
    }

    Ok(HostnameResult {
        common_name,
        san_match,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hostname_matches_exact() {
        assert!(hostname_matches("example.com", "example.com"));
        assert!(hostname_matches("Example.COM", "example.com"));
        assert!(!hostname_matches("example.com", "other.com"));
    }

    #[test]
    fn test_hostname_matches_wildcard() {
        assert!(hostname_matches("*.example.com", "foo.example.com"));
        assert!(hostname_matches("*.example.com", "relay.example.com"));
        assert!(!hostname_matches("*.example.com", "example.com"));
        assert!(!hostname_matches("*.example.com", "foo.bar.example.com"));
    }

    #[test]
    fn test_hostname_result_san_takes_precedence() {
        // SANs present and matched — CN is ignored per RFC 6125
        let result = HostnameResult {
            common_name: Some(heapless::String::try_from("wrong.com").unwrap()),
            san_match: Some(true),
        };
        assert!(result.matches_hostname("anything.com"));

        // SANs present but didn't match — CN is still ignored
        let result = HostnameResult {
            common_name: Some(heapless::String::try_from("wrong.com").unwrap()),
            san_match: Some(false),
        };
        assert!(!result.matches_hostname("wrong.com"));
    }

    #[test]
    fn test_hostname_result_cn_fallback() {
        // No SANs — fall back to CN
        let result = HostnameResult {
            common_name: Some(heapless::String::try_from("example.com").unwrap()),
            san_match: None,
        };
        assert!(result.matches_hostname("example.com"));
        assert!(!result.matches_hostname("other.com"));

        // No SANs, no CN — nothing matches
        let result = HostnameResult {
            common_name: None,
            san_match: None,
        };
        assert!(!result.matches_hostname("example.com"));
    }

    /// Build a minimal DER extensions blob with a SAN extension containing given dNSName entries.
    fn build_san_extension(dns_names: &[&[u8]]) -> ([u8; 128], usize) {
        let mut der = [0u8; 128];
        let mut i = 0;

        // Calculate GeneralNames content length
        let gn_content_len: usize = dns_names.iter().map(|n| 2 + n.len()).sum();
        let oct_len = 2 + gn_content_len; // SEQUENCE tag+len + content
        let ext_len = 5 + 2 + oct_len;    // OID(5) + OCTET STRING tag+len + content

        // Extension SEQUENCE
        der[i] = 0x30; i += 1;
        der[i] = ext_len as u8; i += 1;
        // OID 2.5.29.17
        der[i] = 0x06; i += 1;
        der[i] = 0x03; i += 1;
        der[i] = 0x55; i += 1;
        der[i] = 0x1d; i += 1;
        der[i] = 0x11; i += 1;
        // OCTET STRING
        der[i] = 0x04; i += 1;
        der[i] = oct_len as u8; i += 1;
        // GeneralNames SEQUENCE
        der[i] = 0x30; i += 1;
        der[i] = gn_content_len as u8; i += 1;
        // dNSName entries
        for name in dns_names {
            der[i] = 0x82; i += 1;
            der[i] = name.len() as u8; i += 1;
            der[i..i + name.len()].copy_from_slice(name);
            i += name.len();
        }

        (der, i)
    }

    #[test]
    fn test_san_matches_hostname_match() {
        let (der, len) = build_san_extension(&[b"*.example.com", b"example.com"]);
        // Wildcard match
        assert_eq!(san_matches_hostname(&der[..len], Some("relay.example.com")), Ok(Some(true)));
        // Exact match
        assert_eq!(san_matches_hostname(&der[..len], Some("example.com")), Ok(Some(true)));
        // No match
        assert_eq!(san_matches_hostname(&der[..len], Some("other.com")), Ok(Some(false)));
    }

    #[test]
    fn test_san_matches_hostname_no_san_extension() {
        // Extension with OID 2.5.29.19 (basic constraints), not SAN
        let der: &[u8] = &[
            0x30, 0x0a,
            0x06, 0x03, 0x55, 0x1d, 0x13,
            0x04, 0x03,
            0x30, 0x01, 0x01,
        ];
        assert_eq!(san_matches_hostname(der, Some("example.com")), Ok(None));
    }

    #[test]
    fn test_san_matches_hostname_no_hostname() {
        // When hostname is None, SANs are checked for presence but can't match
        let (der, len) = build_san_extension(&[b"example.com"]);
        assert_eq!(san_matches_hostname(&der[..len], None), Ok(Some(false)));
    }

    #[test]
    fn test_san_rejects_null_bytes() {
        // SAN with embedded null byte should be skipped
        let (der, len) = build_san_extension(&[b"example.com\0.evil.com"]);
        assert_eq!(san_matches_hostname(&der[..len], Some("example.com")), Ok(Some(false)));
    }

    #[test]
    fn test_san_malformed_der_returns_error() {
        // Truncated extension — SEQUENCE claims 0x20 bytes but only 3 follow
        let der: &[u8] = &[0x30, 0x20, 0x06, 0x03, 0x55];
        assert_eq!(san_matches_hostname(der, Some("example.com")), Err(()));

        // Extension with SAN OID but truncated before OCTET STRING content
        let der: &[u8] = &[
            0x30, 0x08,
            0x06, 0x03, 0x55, 0x1d, 0x11, // SAN OID
            0x04, // OCTET STRING tag — but missing length byte
        ];
        assert_eq!(san_matches_hostname(der, Some("example.com")), Err(()));

        // Completely empty — no extensions parsed, no error
        assert_eq!(san_matches_hostname(&[], Some("example.com")), Ok(None));
    }

    #[test]
    fn test_hostname_matches_case_insensitive() {
        assert!(hostname_matches("Example.COM", "example.com"));
        assert!(hostname_matches("example.com", "EXAMPLE.COM"));
        assert!(hostname_matches("*.Example.COM", "relay.example.com"));
        assert!(hostname_matches("*.EXAMPLE.COM", "Relay.Example.Com"));
    }

    #[test]
    fn test_read_tag_len() {
        // Short form
        assert_eq!(read_tag_len(&[0x30, 0x05], 0), Some((0x30, 5, 2)));
        // Long form 1 byte
        assert_eq!(read_tag_len(&[0x30, 0x81, 0x80], 0), Some((0x30, 128, 3)));
        // Long form 2 bytes
        assert_eq!(read_tag_len(&[0x30, 0x82, 0x01, 0x00], 0), Some((0x30, 256, 4)));
        // Too short
        assert_eq!(read_tag_len(&[0x30], 0), None);
    }
}
