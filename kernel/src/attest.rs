// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Tyler Fanelli <tfanelli@redhat.com>

extern crate alloc;

use crate::{
    error::SvsmError,
    greq::{pld_report::*, services::get_regular_report},
    io::{Read, Write, DEFAULT_IO_DRIVER},
    serial::SerialPort,
};
use aes_gcm_siv::{
    aead::{Aead, KeyInit},
    Aes256GcmSiv, Nonce,
};
use alloc::{string::ToString, vec, vec::Vec};
use base64::{prelude::*, Engine};
use cocoon_tpm_crypto::{
    ecc::{curve::Curve, ecdh::ecdh_c_1e_1s_cdh_party_v_key_gen, EccKey},
    rng::{self, HashDrbg, RngCore as _, X86RdSeedRng},
    CryptoError, EmptyCryptoIoSlices,
};
use cocoon_tpm_tpm2_interface::{self as tpm2_interface, TpmEccCurve, TpmiAlgHash, TpmsEccPoint};
use cocoon_tpm_utils_common::{
    alloc::try_alloc_zeroizing_vec,
    io_slices::{self, IoSlicesIterCommon as _},
    zeroize::Zeroizing,
};
use kbs_types::Tee;
use libaproxy::*;
use serde::Serialize;
use sha2::{Digest, Sha512};
use zerocopy::{FromBytes, IntoBytes};

/// The attestation driver that communicates with the proxy via some communication channel (serial
/// port, virtio-vsock, etc...).
#[allow(missing_debug_implementations)]
pub struct AttestationDriver<'a> {
    sp: SerialPort<'a>,
    tee: Tee,
    ecc: EccKey,
    curve: Curve,
    aes_key: Option<Vec<u8>>,
}

impl TryFrom<Tee> for AttestationDriver<'_> {
    type Error = SvsmError;

    fn try_from(tee: Tee) -> Result<Self, Self::Error> {
        // TODO: Make the IO port configurable/discoverable for other transport mechanisms such as
        // virtio-vsock.
        let sp = SerialPort::new(&DEFAULT_IO_DRIVER, 0x3e8); // COM3
        sp.init();

        match tee {
            Tee::Snp => (),
            _ => return Err(AttestationError::UnsupportedTee.into()),
        }

        let curve = Curve::new(TpmEccCurve::NistP384).map_err(AttestationError::Crypto)?;
        let ecc = sc_key_generate(&curve).map_err(AttestationError::Crypto)?;

        Ok(Self {
            sp,
            tee,
            ecc,
            curve,
            aes_key: None,
        })
    }
}

impl AttestationDriver<'_> {
    /// Attest SVSM's launch state by communicating with the attestation proxy.
    pub fn attest(&mut self) -> Result<Vec<u8>, SvsmError> {
        let negotiation = self.negotiation()?;

        self.attestation(negotiation)
            .map_err(SvsmError::TeeAttestation)
    }

    pub fn syncback(&mut self, secret: Vec<u8>) -> Result<SyncBackResponse, SvsmError> {
        Ok(self.sync(secret)?)
    }

    /// Send a negotiation request to the proxy. Proxy should reply with Negotiation parameters
    /// that should be included in attestation evidence (e.g. through SEV-SNP's REPORT_DATA
    /// mechanism).
    fn negotiation(&mut self) -> Result<NegotiationResponse, AttestationError> {
        let request = NegotiationRequest {
            version: "0.1.0".to_string(), // Only version supported at present.
            tee: self.tee,
        };

        self.write(request)?;
        let payload = self.read()?;

        serde_json::from_slice(&payload).or(Err(AttestationError::NegotiationDeserialize))
    }

    /// Send an attestation request to the proxy. Proxy should reply with attestation response
    /// containing the status (success/fail) and an optional secret returned from the server upon
    /// successful attestation.
    fn attestation(&mut self, n: NegotiationResponse) -> Result<Vec<u8>, AttestationError> {
        let pub_key = self
            .ecc
            .pub_key()
            .to_tpms_ecc_point(&self.curve.curve_ops().map_err(AttestationError::Crypto)?)
            .map_err(AttestationError::Crypto)?;

        let evidence = evidence(&self.tee, hash(n, &pub_key)?)?;

        let req = AttestationRequest {
            evidence: BASE64_URL_SAFE.encode(evidence),
            key: (TpmEccCurve::NistP384, &pub_key)
                .try_into()
                .map_err(|_| AttestationError::AttestationDeserialize)?,
        };

        self.write(req)?;
        let payload = self.read()?;

        let response: AttestationResponse = serde_json::from_slice(&payload)
            .map_err(|_| AttestationError::AttestationDeserialize)?;

        if !response.success {
            return Err(AttestationError::Failed);
        }

        let Some(ak) = response.pub_key else {
            return Err(AttestationError::PublicKeyMissing)?;
        };

        let pub_key: TpmsEccPoint<'static> = ak.try_into().map_err(AttestationError::Crypto)?;

        let Some(ciphertext) = response.secret else {
            return Err(AttestationError::SecretMissing);
        };

        let Some(nonce) = response.nonce else {
            return Err(AttestationError::SecretMissing);
        };

        self.decrypt(ciphertext, nonce, pub_key)
    }

    fn sync(&mut self, secret: Vec<u8>) -> Result<SyncBackResponse, AttestationError> {
        let (nonce, secret) = self.encrypt(secret)?;

        let request = SyncBackRequest { nonce, secret };

        self.write(request)?;
        let payload = self.read()?;

        serde_json::from_slice(&payload).or(Err(AttestationError::SyncBackRespDeserialize))
    }

    /// Decrypt a secret from the attestation server with the TEE private key.
    fn decrypt(
        &mut self,
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        pub_key: TpmsEccPoint<'static>,
    ) -> Result<Vec<u8>, AttestationError> {
        let shared_secret =
            ecdh_c_1e_1s_cdh_party_v_key_gen(TpmiAlgHash::Sha256, "", &self.ecc, &pub_key)
                .map_err(AttestationError::Crypto)?;

        self.aes_key = Some(shared_secret[..].to_vec());

        let aes = Aes256GcmSiv::new_from_slice(&shared_secret[..])
            .or(Err(AttestationError::AesGenerate))?;
        let aes_nonce = Nonce::from_slice(&nonce);

        let decrypt = aes
            .decrypt(aes_nonce, ciphertext.as_ref())
            .or(Err(AttestationError::SecretDecrypt))?;

        Ok(decrypt)
    }

    fn encrypt(&mut self, secret: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), AttestationError> {
        let rand = aes_nonce_generate().map_err(AttestationError::Crypto)?;

        let cipher = Aes256GcmSiv::new_from_slice(self.aes_key.as_ref().unwrap());
        let nonce = Nonce::from_slice(&rand);

        let encrypted_secret = cipher.unwrap().encrypt(nonce, secret.as_slice()).unwrap();

        Ok((Vec::from(nonce.as_bytes()), encrypted_secret))
    }

    /// Read attestation data from the serial port.
    fn read(&mut self) -> Result<Vec<u8>, AttestationError> {
        let len = {
            let mut bytes = [0u8; 8];
            self.sp
                .read(&mut bytes)
                .or(Err(AttestationError::ProxyRead))?;

            usize::from_ne_bytes(bytes)
        };

        let mut buf = vec![0u8; len];
        self.sp
            .read(&mut buf)
            .or(Err(AttestationError::ProxyRead))?;

        Ok(buf)
    }

    /// Write attestation data over the serial port.
    fn write(&mut self, param: impl Serialize) -> Result<(), AttestationError> {
        let bytes = serde_json::to_vec(&param).or(Err(AttestationError::NegotiationSerialize))?;

        // The receiving party is unaware of how many bytes to read from the port. Write an 8-byte
        // header indicating the length of the buffer before writing the buffer itself.
        self.sp
            .write(&bytes.len().to_ne_bytes())
            .or(Err(AttestationError::ProxyWrite))?;
        self.sp
            .write(&bytes)
            .or(Err(AttestationError::ProxyWrite))?;

        Ok(())
    }
}

/// Possible errors when attesting TEE evidence.
#[derive(Clone, Copy, Debug)]
pub enum AttestationError {
    /// Error generating AES key.
    AesGenerate,
    /// Error deserializing the attestation response from JSON bytes.
    AttestationDeserialize,
    /// Guest has failed attestation.
    Failed,
    /// Error deserializing the negotiation response from JSON bytes.
    NegotiationDeserialize,
    /// Error serializing the negotiation request to JSON bytes.
    NegotiationSerialize,
    /// Error reading from the attestation proxy transport channel.
    ProxyRead,
    /// Error writing over the attestation proxy transport channel.
    ProxyWrite,
    /// Attestation successful, but no public key found.
    PublicKeyMissing,
    /// Unsupported TEE architecture.
    UnsupportedTee,
    /// Unable to generate secure channel key.
    Crypto(CryptoError),
    /// Attestation successful, but unable to decrypt secret.
    SecretDecrypt,
    /// Attestation successful, but no secret found.
    SecretMissing,
    /// Unable to fetch SEV-SNP attestation report.
    SnpGetReport,
    /// Error deserializing the syncback response from JSON bytes.
    SyncBackRespDeserialize,
}

impl From<AttestationError> for SvsmError {
    fn from(e: AttestationError) -> Self {
        Self::TeeAttestation(e)
    }
}

/// Generate a key used to establish a secure channel between the confidential guest and
/// attestation server.
fn sc_key_generate(curve: &Curve) -> Result<EccKey, CryptoError> {
    let mut rng = {
        let mut rdseed = X86RdSeedRng::instantiate().map_err(|_| CryptoError::RngFailure)?;
        let mut hash_drbg_entropy =
            try_alloc_zeroizing_vec(HashDrbg::min_seed_entropy_len(TpmiAlgHash::Sha256))?;

        rdseed.generate::<_, EmptyCryptoIoSlices>(
            io_slices::SingletonIoSliceMut::new(hash_drbg_entropy.as_mut_slice())
                .map_infallible_err(),
            None,
        )?;

        rng::HashDrbg::instantiate(
            tpm2_interface::TpmiAlgHash::Sha256,
            &hash_drbg_entropy,
            None,
            Some(b"SVSM attestation RNG"),
        )
    }?;

    let curve_ops = curve.curve_ops()?;

    EccKey::generate(&curve_ops, &mut rng, None)
}

fn aes_nonce_generate() -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let mut rdseed = X86RdSeedRng::instantiate().map_err(|_| CryptoError::RngFailure)?;
    let mut hash_drbg_entropy = try_alloc_zeroizing_vec(12)?;

    rdseed.generate::<_, EmptyCryptoIoSlices>(
        io_slices::SingletonIoSliceMut::new(hash_drbg_entropy.as_mut_slice()).map_infallible_err(),
        None,
    )?;

    Ok(hash_drbg_entropy)
}

/// Hash negotiation parameters and fetch TEE evidence.
fn evidence(tee: &Tee, hash: Vec<u8>) -> Result<Vec<u8>, AttestationError> {
    let evidence = match tee {
        &Tee::Snp => {
            let mut user_data = [0u8; 64];
            user_data.copy_from_slice(&hash);

            let request = SnpReportRequest {
                user_data,
                vmpl: 0,
                flags: 1, // Sign with VCEK.
                rsvd: [0u8; 24],
            };

            let mut buf = request.as_bytes().to_vec();
            // The buffer currently contains the the SnpReportRequest structure. However, SVSM
            // will fill this buffer in with the SnpReportResponse when fetching the report.
            // Ensure the array is large enough to contain the response (which is much larger
            // than the request, as it contains the attestation report).
            buf.resize(2048, 0);

            let bytes = {
                let len = get_regular_report(&mut buf).or(Err(AttestationError::SnpGetReport))?;

                // We have the length of the response. The rest of the response is unused.
                // Parse the SnpReportResponse from the slice of the buf containing the
                // response (that is, &buf[0..len]).
                let resp = SnpReportResponse::ref_from_bytes(&buf[..len])
                    .or(Err(AttestationError::SnpGetReport))?;

                // Get the attestation report as bytes for serialization in the
                // AttestationRequest.
                resp.report().as_bytes().to_vec()
            };

            bytes
        }
        // We check for supported TEE architectures in the AttestationDriver's constructor.
        _ => unreachable!(),
    };

    Ok(evidence)
}

/// Hash the negotiation parameters from the attestation server for inclusion in the
/// attestation evidence.
fn hash(
    n: NegotiationResponse,
    pub_key: &TpmsEccPoint<'static>,
) -> Result<Vec<u8>, AttestationError> {
    let mut sha = Sha512::new();

    for p in &n.params {
        match p {
            NegotiationParam::Base64StdBytes(s) => {
                let decoded = BASE64_STANDARD
                    .decode(s)
                    .map_err(|_| AttestationError::NegotiationDeserialize)?;

                sha.update(decoded);
            }
            #[allow(irrefutable_let_patterns)]
            NegotiationParam::EcPublicKeyBytes => {
                sha.update(&*pub_key.x.buffer);
                sha.update(&*pub_key.y.buffer);
            }
        }
    }

    Ok(sha.finalize().to_vec())
}
