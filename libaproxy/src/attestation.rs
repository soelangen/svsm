// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Tyler Fanelli <tfanelli@redhat.com>

extern crate alloc;
use alloc::string::String;
use serde::{Deserialize, Serialize};

/// The format of the public key that is used to encrypt secrets sent to SVSM upon successful
/// attestation.
///
/// Based on JSON Web Key
/// See for examples: <https://www.rfc-editor.org/rfc/rfc7517#appendix-A.1>
#[derive(Serialize, Deserialize, Debug)]
pub enum AttestationKey {
    RSA { n: String, e: String },
    EC { crv: String, x: String, y: String },
}

/// The attestation request payload sent to the proxy from SVSM.
#[derive(Serialize, Deserialize, Debug)]
pub struct AttestationRequest {
    /// Attestation evidence generated by SVSM
    pub evidence: String,
    /// Public key generated by SVSM to receive the secret
    pub key: AttestationKey,
}

/// Response from proxy to SVSM indicating the status of attestation as well as an optional secret
/// if successful.
#[derive(Serialize, Deserialize, Debug)]
pub struct AttestationResponse {
    /// Remote attestation result
    pub success: bool,
    /// Secret encrypted with the key generated by SVSM
    pub secret: Option<String>,
}