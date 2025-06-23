// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025 Sören Langenberg
//
// Author: Sören Langenberg <soeren.langenberg@mailbox.org>

extern crate alloc;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// The syncback request payload sent to the proxy from the SVSM
#[derive(Serialize, Deserialize, Debug)]
pub struct SyncBackRequest {
    // The nonce needed for AES encryption
    pub nonce: Vec<u8>,
    // Secret encrypted with the AES key
    pub secret: Vec<u8>,
}

/// Resoibse from proxy to the SVSM indicating the status
#[derive(Serialize, Deserialize, Debug)]
pub struct SyncBackResponse {
    pub success: bool,
}
