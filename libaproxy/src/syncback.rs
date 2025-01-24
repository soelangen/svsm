// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025 Sören Langenberg
//
// Author: Sören Langenberg <soeren.langenberg@mailbox.org>

extern crate alloc;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// The synback request payload sent to the proxy from SVSM
#[derive(Serialize, Deserialize, Debug)]
pub struct SyncBackRequest {
    /// The nonce needed for AES encryption
    pub nonce: Vec<u8>,
    /// Secret encrypted with the AES key
    pub secret: Vec<u8>,
    /// The family_id used for identification
    pub family_id: [u8; 16],
    /// The image_id used for identification
    pub image_id: [u8; 16],
}

/// Response from proxy to SVSM indicating the status
#[derive(Serialize, Deserialize, Debug)]
pub struct SyncBackResponse {
    /// Result of SyncBack
    pub success: bool,
}
