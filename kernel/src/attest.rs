// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Tyler Fanelli <tfanelli@redhat.com>

extern crate alloc;

use crate::{
    error::SvsmError,
    greq::{
        pld_report::{SnpReportRequest, SnpReportResponse},
        services::get_regular_report,
    },
    io::{Read, Write, DEFAULT_IO_DRIVER},
    serial::SerialPort,
};
use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};
use aes_gcm_siv::{
    aead::{Aead, KeyInit},
    Aes256GcmSiv, Nonce
};
use base64::prelude::*;
use kbs_types::Tee;
use libaproxy::*;
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use rdrand::RdSeed;
use rsa::{traits::PublicKeyParts, Pkcs1v15Encrypt, RsaPrivateKey};
use serde::Serialize;
use sha2::{Digest, Sha384, Sha512};
use zerocopy::{FromBytes, IntoBytes};

/// The attestation driver that communicates with the proxy via some communication channel (serial
/// port, virtio-vsock, etc...).
#[derive(Debug)]
pub struct AttestationDriver<'a> {
    sp: SerialPort<'a>,
    tee: Tee,
    key: Option<TeeKey>,
}

impl TryFrom<Tee> for AttestationDriver<'_> {
    type Error = SvsmError;

    fn try_from(tee: Tee) -> Result<Self, Self::Error> {
        let sp = SerialPort::new(&DEFAULT_IO_DRIVER, 0x3e8); // COM3
        sp.init();

        match tee {
            Tee::Snp => (),
            _ => return Err(AttestationError::UnsupportedTee.into()),
        }

        Ok(Self { sp, tee, key: None })
    }
}

impl AttestationDriver<'_> {
    /// Attest SVSM's launch state by communicating with the attestation proxy.
    pub fn attest(&mut self) -> Result<Vec<u8>, SvsmError> {
        let negotiation = self.negotiation()?;

        Ok(self.attestation(negotiation)?)
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

        serde_json::from_slice(&payload).or(Err(AttestationError::NegotiationRespDeserialize))
    }

    /// Send an attestation request to the proxy. Proxy should reply with attestation response
    /// containing the status (success/fail) and an optional secret returned from the server upon
    /// successful attestation.
    fn attestation(
        &mut self,
        negotiation: NegotiationResponse,
    ) -> Result<Vec<u8>, AttestationError> {
        // Generate TEE key and evidence for serialization to proxy.
        self.tee_key_generate(&negotiation)?;
        let evidence = self.evidence(negotiation)?;

        // Safe to unwrap at this point.
        let key = &self.key.clone().unwrap();

        let request = AttestationRequest {
            evidence: BASE64_STANDARD.encode(evidence),
            key: AttestationKey::from(key),
        };

        self.write(request)?;

        let payload = self.read()?;
        let response: AttestationResponse = serde_json::from_slice(&payload)
            .or(Err(AttestationError::AttestationRespDeserialize))?;

        if !response.success {
            return Err(AttestationError::Failed);
        }

        let aes_key = response.aes_key.ok_or(AttestationError::SecretNotFound)?;
        let nonce = response.nonce.ok_or(AttestationError::SecretNotFound)?;
        let secret = response.secret.ok_or(AttestationError::SecretNotFound)?;

        self.secret_decrypt(aes_key, nonce, secret)
    }

    /// Generate the TEE attestation key.
    fn tee_key_generate(
        &mut self,
        negotiation: &NegotiationResponse,
    ) -> Result<(), AttestationError> {
        let key = match negotiation.key_type {
            NegotiationKey::RSA3072 => TeeKey::rsa(3072)?,
            NegotiationKey::RSA4096 => TeeKey::rsa(4096)?,
            _ => return Err(AttestationError::UnsupportedTeeKeyAlg),
        };

        self.key = Some(key);

        Ok(())
    }

    /// Hash negotiation parameters and fetch TEE evidence.
    fn evidence(&self, negotiation: NegotiationResponse) -> Result<Vec<u8>, AttestationError> {
        let mut hash = match negotiation.hash {
            NegotiationHash::SHA384 => self.hash(&negotiation, Sha384::new())?,
            NegotiationHash::SHA512 => self.hash(&negotiation, Sha512::new())?,
        };

        let evidence = match self.tee {
            Tee::Snp => {
                // SEV-SNP REPORT_DATA is 64 bytes in size. If a SHA384 was selected in the
                // negotiation parameters, that array is 48 bytes in size and must be padded.
                hash.resize(64, 0);

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
                    let len =
                        get_regular_report(&mut buf).or(Err(AttestationError::SnpGetReport))?;

                    // We have the length of the response. The rest of the response is unused.
                    // Parse the SnpReportResponse from the slice of the buf containing the
                    // response (that is, &buf[0..len]).
                    let resp = SnpReportResponse::ref_from_bytes(&buf[..len])
                        .or(Err(AttestationError::SnpResponseParse))?;

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
        &self,
        n: &NegotiationResponse,
        mut sha: impl Digest,
    ) -> Result<Vec<u8>, AttestationError> {
        for p in &n.params {
            match p {
                NegotiationParam::Base64StdBytes(s) => {
                    let decoded = BASE64_STANDARD
                        .decode(s)
                        .or(Err(AttestationError::Base64StdDecode))?;

                    sha.update(decoded);
                }
                NegotiationParam::TeeKeyPublicComponents => {
                    let key = &self.key.clone().unwrap(); // Safe to unwrap.
                    key.hash(&mut sha);
                }
            }
        }

        Ok(sha.finalize().to_vec())
    }

    /// Decrypt a secret from the attestation server with the TEE private key.
    fn secret_decrypt(&self, aes_key:String, nonce:String, encrypted: String) -> Result<Vec<u8>, AttestationError> {

        let aes_key_bytes = BASE64_STANDARD
            .decode(aes_key.as_bytes())
            .or(Err(AttestationError::SecretDecode))?;

        let nonce_bytes = BASE64_STANDARD
            .decode(nonce.as_bytes())
            .or(Err(AttestationError::SecretDecode))?;

        let bytes = BASE64_STANDARD
            .decode(encrypted)
            .or(Err(AttestationError::SecretDecode))?;

        // Safe to unwrap.
        let decrypted_result = match self.key.clone().unwrap() {
            TeeKey::Rsa(rsa) => rsa
                .decrypt(Pkcs1v15Encrypt, &aes_key_bytes)
        };

        let cipher = Aes256GcmSiv::new_from_slice(&decrypted_result.unwrap());
        let nonce = Nonce::from_slice(&nonce_bytes);

        match cipher.unwrap().decrypt(nonce, bytes.as_ref()){
         Ok(decrypted) => Ok(decrypted),
            Err(_) => Err(AttestationError::SecretDecode)
        }
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
        let bytes = serde_json::to_vec(&param).or(Err(AttestationError::JsonSerialize))?;

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

/// TEE key used to decrypt secrets sent from the attestation server.
#[derive(Clone, Debug)]
pub enum TeeKey {
    Rsa(RsaPrivateKey),
}

impl TeeKey {
    /// Generate an RSA key as the TEE key.
    fn rsa(bits: usize) -> Result<Self, AttestationError> {
        let mut rdseed = RdSeed::new().or(Err(AttestationError::RdRandUsage))?;
        let mut rng = ChaChaRng::from_rng(&mut rdseed).or(Err(AttestationError::TeeKeyGenerate))?;

        let rsa = RsaPrivateKey::new(&mut rng, bits).or(Err(AttestationError::TeeKeyGenerate))?;

        Ok(Self::Rsa(rsa))
    }

    /// Hash the public components of the TEE key.
    fn hash(&self, sha: &mut impl Digest) {
        match self {
            Self::Rsa(rsa) => {
                let public = rsa.to_public_key();

                sha.update(public.n().to_bytes_be());
                sha.update(public.e().to_bytes_be());
            }
        }
    }
}

impl From<&TeeKey> for AttestationKey {
    fn from(key: &TeeKey) -> AttestationKey {
        match key {
            TeeKey::Rsa(rsa) => {
                let public = rsa.to_public_key();

                AttestationKey::RSA {
                    n: BASE64_URL_SAFE.encode(public.n().to_bytes_be()),
                    e: BASE64_URL_SAFE.encode(public.e().to_bytes_be()),
                }
            }
        }
    }
}

/// Possible errors when attesting TEE evidence.
#[derive(Clone, Copy, Debug)]
pub enum AttestationError {
    // Unable to deserialize response from proxy into libaproxy::AttestationResponse.
    AttestationRespDeserialize,
    // Unable to decode bytes from Base64 standard.
    Base64StdDecode,
    // Attestation was invalid.
    Failed,
    // Error serializing an object to a JSON Vec.
    JsonSerialize,
    // Unable to deserialize response from proxy into libaproxy::NegotiationResponse.
    NegotiationRespDeserialize,
    // Error while reading from proxy's transport channel.
    ProxyRead,
    // Error while writing to proxy's transport channel.
    ProxyWrite,
    // RDRAND/RDSEED error.
    RdRandUsage,
    // Attestation was successful, yet secret was not found.
    SecretNotFound,
    // Secret found, but unable to be decoded from base64.
    SecretDecode,
    // Unable to decrypt secret with TEE private key.
    SecretDecryption,
    // Error fetching SEV-SNP attestation report from PSP.
    SnpGetReport,
    // Error parsing the SnpReportResponse from the SNP_GET_REPORT.
    SnpResponseParse,
    // Unable to generate the TEE key.
    TeeKeyGenerate,
    // Unsupported TEE architecture.
    UnsupportedTee,
    // Unsupported algorithm for generating a TEE key.
    UnsupportedTeeKeyAlg,
}

impl From<AttestationError> for SvsmError {
    fn from(e: AttestationError) -> Self {
        Self::Attestation(e)
    }
}