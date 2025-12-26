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
    blob_bytes_to_commitment, blob_to_commitment, compute_proof, verify_proof,
};
