// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Tyler Fanelli <tfanelli@redhat.com>

use super::*;
use anyhow::Context;
use kbs_types::{Attestation, Challenge, Request, Response, Tee, TeePubKey};
use reqwest::StatusCode;
use serde_json::Value;

#[derive(Clone, Copy, Debug, Default)]
pub struct KbsProtocol;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncRequest {
    pub nonce: Vec<u8>,
    pub secret: Vec<u8>,
    pub family_id: [u8; 16],
    pub image_id: [u8; 16],
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncResponse {
    pub success: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceRequest {
    pub family_id: [u8; 16],
    pub image_id: [u8; 16],
}

impl AttestationProtocol for KbsProtocol {
    /// KBS servers usually want two components hashed into attestation evidence: the public
    /// components of the TEE key, and a nonce provided in the KBS challenge that is fetched
    /// from the server's /auth endpoint. These must be hased in order.
    ///
    /// Make this request to /auth, gather the nonce, and return this in the negotiation
    /// parameter for SVSM to hash these components in the attestation evidence.
    fn negotiation(
        cli: &Client,
        url: &str,
        request: NegotiationRequest,
    ) -> anyhow::Result<NegotiationResponse> {
        let req = Request {
            version: "0.1.0".to_string(), // unused.
            tee: request.tee,
            extra_params: Value::String("".to_string()), // unused.
        };

        // Fetch challenge containing a nonce from the KBS /auth endpoint.
        let http_resp = cli
            .post(format!("{}/kbs/v0/auth", url))
            .json(&req)
            .send()
            .context("unable to POST to KBS /auth endpoint")?;

        let text = http_resp
            .text()
            .context("unable to convert KBS /auth response to text")?;

        let challenge: Challenge =
            serde_json::from_str(&text).context("unable to convert KBS /auth response to JSON")?;

        // Challenge nonce is a base64-encoded byte vector. Inform SVSM of this so it could
        // decode the bytes and hash them into the TEE evidence.
        let params = vec![
            NegotiationParam::EcPublicKeySec1Bytes,
            NegotiationParam::Base64StdBytes(challenge.nonce),
        ];

        // SEV-SNP REPORT_DATA is 64 bytes in size. Produce a SHA512 hash to ensure there's no need
        // for padding.
        let hash = match request.tee {
            Tee::Snp => NegotiationHash::SHA512,
            _ => return Err(anyhow!("invalid TEE architecture selected")),
        };

        let resp = NegotiationResponse {
            hash,
            key_type: NegotiationKey::Ecdh384Sha256Aes128,
            params,
        };

        Ok(resp)
    }

    /// With the serialized TEE evidence and key, complete the attestation. Serialize the evidence
    /// and send it to the /attest endpoint of the KBS server. Upon a successful attestation, fetch
    /// a secret (identified as "svsm_secret"). If able to successfully fetch the secret, return a
    /// successful AttestationResponse with the secret included.
    fn attestation(
        cli: &Client,
        url: &str,
        request: AttestationRequest,
    ) -> anyhow::Result<AttestationResponse> {
        // Create a KBS attestation object from the TEE evidence and key.
        let attestation = Attestation {
            tee_pubkey: match request.key {
                AttestationKey::EC {
                    crv,
                    x_b64url,
                    y_b64url,
                } => TeePubKey::EC {
                    crv,
                    alg: "EC".to_string(),
                    x: x_b64url,
                    y: y_b64url,
                },
            },
            tee_evidence: Value::String(request.evidence),
        };

        // Attest TEE evidence at KBS /attest endpoint.
        let http_resp = cli
            .post(format!("{}/kbs/v0/attest", url))
            .json(&attestation)
            .send()
            .context("unable to POST to KBS /attest endpoint")?;

        // The JSON response from the /attest endpoint is basically ignored here. Instead, we check
        // the HTTP status to indicate successful attestation.
        //
        // FIXME
        if http_resp.status() != StatusCode::OK {
            return Ok(AttestationResponse {
                nonce: None,
                success: false,
                secret: None,
                pub_key: None,
            });
        }

        let resource = ResourceRequest {
            family_id: request.family_id,
            image_id: request.image_id,
        };

        // Successful attestation. Fetch the secret (which should be stored as "svsm_secret" within
        // the KBS's RVPS.
        let http_resp = cli
            .post(format!("{}/kbs/v0/svsm_secret", url))
            .json(&resource)
            .send()
            .context("unable to POST to KBS /attest endpoint")?;

        // Unsuccessful attempt at retrieving secret.
        if http_resp.status() != StatusCode::OK {
            return Ok(AttestationResponse {
                nonce: None,
                success: false,
                secret: None,
                pub_key: None,
            });
        }

        let text = http_resp
            .text()
            .context("unable to read KBS /resource response")?;

        let resp: Response = serde_json::from_str(&text)
            .context("unable to convert KBS /resource response to KBS Response object")?;

        Ok(AttestationResponse {
            nonce: Some(resp.iv),
            success: true,
            secret: Some(resp.ciphertext),
            pub_key: Some(resp.encrypted_key),
        })
    }

    // TODO also use the /resource endpoint however with a post instead of get
    // Do that according to spec --> Currently the syncback endpoint is sufficient for testing
    // https://github.com/confidential-containers/trustee/blob/main/kbs/docs/kbs_attestation_protocol.md#resource-registration-experimental
    fn syncback(
        cli: &Client,
        url: &str,
        request: SyncBackRequest,
    ) -> anyhow::Result<SyncBackResponse> {
        let req = SyncRequest {
            nonce: request.nonce,
            secret: request.secret,
            family_id: request.family_id,
            image_id: request.image_id,
        };
        // Send secret to synback endpoint
        let http_resp = cli
            .post(format!("{}/kbs/v0/syncback", url))
            .json(&req)
            .send()
            .context("unable to POST to KBS /syncback endpoint")?;

        let text = http_resp
            .text()
            .context("unable to convert KBS /syncback response to text")?;

        let resp: SyncResponse = serde_json::from_str(&text)
            .context("unable to convert KBS /syncback response to JSON")?;

        Ok(SyncBackResponse {
            success: resp.success,
        })
    }
}
