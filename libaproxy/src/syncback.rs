// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025 Sören Langenberg
//
// Author: Sören Langenberg <soeren.langenberg@mailbox.org>

extern crate alloc;
use alloc::string::String;
use serde::{Deserialize, Serialize};

/// The synback request payload sent to the proxy from SVSM
#[derive(Serialize, Deserialize, Debug)]
pub struct SyncBackRequest {
    /// The nonce needed for AES encryption
    pub nonce: String,
    /// Secret encrypted with the AES key
    pub secret: String,
}

/// Response from proxy to SVSM indicating the status
#[derive(Serialize, Deserialize, Debug)]
pub struct SyncBackResponse {
    /// Result of SyncBack
    pub success: bool,
}
