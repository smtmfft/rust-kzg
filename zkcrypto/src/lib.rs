//! # rust-kzg-zkcrypto
//!
//! Simplified KZG API for EIP-4844, built on top of the zkcrypto backend.
//!
//! ## Quick Start
//!
//! ```rust
//! use rust_kzg_zkcrypto::{load_trusted_setup, blob_bytes_to_commitment, compute_proof, verify_proof};
//!
//! // Load KZG settings (returns KZGSettings - you don't need to know the internal types)
//! let settings = load_trusted_setup("trusted_setup.txt")?;
//!
//! // Compute commitment from blob bytes
//! let blob_bytes = [0u8; 131072]; // BYTES_PER_BLOB
//! let commitment = blob_bytes_to_commitment(&blob_bytes, &settings)?;
//!
//! // Compute proof
//! let blob = kzg::eip_4844::bytes_to_blob(&blob_bytes)?;
//! let proof = compute_proof(&blob, &commitment, &settings)?;
//!
//! // Verify proof
//! let verified = verify_proof(&blob, &commitment, &proof, &settings)?;
//! ```
//!
//! ## Type Information
//!
//! All simplified API functions use fixed types internally (ZFr, ZG1, ZG2, etc.),
//! so you don't need to specify type parameters. The return types are:
//! - `load_trusted_setup()` → `KZGSettings`
//! - `blob_to_commitment()` → `ZG1`
//! - `compute_proof()` → `ZG1`
//! - `verify_proof()` → `bool`
//!
//! If you need to work with these types directly (e.g., for serialization),
//! they are exported at the crate root: `rust_kzg_zkcrypto::{KZGSettings, ZG1, ZFr}`.

pub mod consts;
pub mod das;
pub mod eip_4844;
pub mod eip_7594;
pub mod fft;
pub mod fft_g1;
pub mod fk20_proofs;
pub mod kzg_proofs;
pub mod kzg_types;
pub mod poly;
pub mod recover;
pub mod utils;
pub mod zero_poly;

/// Type aliases to simplify template parameters in API calls
/// 
/// Usage example:
/// ```rust
/// use rust_kzg_zkcrypto::types::*;
/// use kzg::eip_4844::blob_to_kzg_commitment_rust;
/// 
/// let commitment = blob_to_kzg_commitment_rust::<
///     ZFr, ZG1, ZG2, FFTSettings, PolyData, KZGSettings,
///     ZFp, ZG1Affine, ZG1ProjAddAffine,
/// >(&blob, &settings)?;
/// ```
pub mod types {
    pub use crate::kzg_proofs::{FFTSettings, KZGSettings};
    pub use crate::kzg_types::{ZFp, ZFr, ZG1, ZG1Affine, ZG1ProjAddAffine, ZG2};
    pub use crate::poly::PolyData;
}

/// Simplified API wrapper to avoid specifying template parameters on every call
mod api;
pub use api::{
    blob_bytes_to_commitment, blob_to_commitment, compute_proof, load_trusted_setup, verify_proof,
};

#[cfg(feature = "bincode")]
pub use api::{load_trusted_setup_from_binary, save_trusted_setup};

// Re-export commonly used types for convenience
// Users don't need to know about ZFr, ZG1, etc. - they can just use the simplified API.
// But if they need to work with the types directly (e.g., for serialization), they're available here.
pub use crate::kzg_proofs::KZGSettings;
pub use crate::kzg_types::{ZG1, ZFr};
