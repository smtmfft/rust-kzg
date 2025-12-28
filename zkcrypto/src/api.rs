//! Simplified API wrapper to avoid specifying template parameters on every call
//!
//! These functions internally specify all necessary type parameters, making them easier to use.

#[cfg(feature = "std")]
use crate::eip_4844::load_trusted_setup_filename_rust as load_trusted_setup_from_file;
use crate::kzg_proofs::{FFTSettings, KZGSettings};
use crate::kzg_types::{ZFp, ZFr, ZG1Affine, ZG1ProjAddAffine, ZG1, ZG2};
use crate::poly::PolyData;
use kzg::eip_4844::{
    blob_to_kzg_commitment_rust, bytes_to_blob, compute_blob_kzg_proof_rust,
    verify_blob_kzg_proof_rust,
};

/// Load KZG settings from a trusted setup text file (simplified version)
///
/// This function loads the trusted setup from a text file and returns a `KZGSettings`
/// instance with all type parameters already specified. You don't need to know
/// the internal types (ZFr, ZG1, etc.) - just use the returned `KZGSettings`.
///
/// **Note:** Loading from text file is slow (takes 10-80 seconds) because it needs to:
/// - Parse the text file (800KB+)
/// - Deserialize 4096 G1 points and 65 G2 points
/// - Compute FFT settings
/// - Compute x_ext_fft_columns (64 FFT operations)
/// - Generate precomputation tables (if enabled)
///
/// For faster loading, consider serializing the settings to binary format first
/// using `save_trusted_setup`, then loading with `load_trusted_setup_from_binary`.
///
/// # Arguments
/// - `filepath`: Path to the trusted setup text file
///
/// # Returns
/// - `Ok(KZGSettings)`: KZG settings ready to use
/// - `Err(String)`: error message
///
/// # Example
/// ```rust
/// use rust_kzg_zkcrypto::load_trusted_setup;
///
/// let settings = load_trusted_setup("path/to/trusted_setup.txt")?;
/// ```
pub fn load_trusted_setup(filepath: &str) -> Result<KZGSettings, String> {
    #[cfg(feature = "std")]
    return load_trusted_setup_from_file(filepath);
    #[cfg(not(feature = "std"))]
    return Err("load_trusted_setup is not supported in this configuration".to_string());
}

/// Save KZG settings to a binary file (simplified version)
///
/// This function serializes `KZGSettings` to a binary file using `bincode`.
/// Loading from binary is much faster (seconds) than loading from text file (minutes).
///
/// **Requires:** `bincode` feature to be enabled.
///
/// # Arguments
/// - `settings`: KZG settings to serialize
/// - `filepath`: Path where to save the binary file
///
/// # Returns
/// - `Ok(())`: Success
/// - `Err(String)`: error message
///
/// # Example
/// ```rust
/// use rust_kzg_zkcrypto::{load_trusted_setup, save_trusted_setup};
///
/// // First time: load from text file (slow)
/// let settings = load_trusted_setup("trusted_setup.txt")?;
///
/// // Save to binary for faster loading next time
/// save_trusted_setup(&settings, "settings.bin")?;
/// ```
#[cfg(feature = "bincode")]
pub fn save_trusted_setup(settings: &KZGSettings, filepath: &str) -> Result<(), String> {
    use std::fs;
    let serialized = bincode::serialize(settings)
        .map_err(|e| format!("Failed to serialize KZGSettings: {}", e))?;
    fs::write(filepath, &serialized).map_err(|e| format!("Failed to write binary file: {}", e))?;
    Ok(())
}

/// Load KZG settings from a binary file (simplified version)
///
/// This function deserializes `KZGSettings` from a binary file created by `save_trusted_setup`.
/// This is much faster (seconds) than loading from text file (minutes).
///
/// **Requires:** `bincode` feature to be enabled.
///
/// # Arguments
/// - `filepath`: Path to the binary file
///
/// # Returns
/// - `Ok(KZGSettings)`: KZG settings ready to use
/// - `Err(String)`: error message
///
/// # Example
/// ```rust
/// use rust_kzg_zkcrypto::load_trusted_setup_from_binary;
///
/// // Fast loading from binary file
/// let settings = load_trusted_setup_from_binary("settings.bin")?;
/// ```
#[cfg(feature = "bincode")]
pub fn load_trusted_setup_from_binary(filepath: &str) -> Result<KZGSettings, String> {
    use std::fs;
    let binary_data =
        fs::read(filepath).map_err(|e| format!("Failed to read binary file: {}", e))?;
    bincode::deserialize(&binary_data)
        .map_err(|e| format!("Failed to deserialize KZGSettings: {}", e))
}

/// Compute KZG commitment from blob (simplified version)
///
/// # Arguments
/// - `blob`: blob as field elements
/// - `settings`: KZG settings
///
/// # Returns
/// - `Ok(ZG1)`: commitment
/// - `Err(String)`: error message
pub fn blob_to_commitment(blob: &[ZFr], settings: &KZGSettings) -> Result<ZG1, String> {
    blob_to_kzg_commitment_rust::<
        ZFr,
        ZG1,
        ZG2,
        FFTSettings,
        PolyData,
        KZGSettings,
        ZFp,
        ZG1Affine,
        ZG1ProjAddAffine,
    >(blob, settings)
}

/// Compute KZG commitment from blob bytes (simplified version)
///
/// # Arguments
/// - `blob_bytes`: blob as bytes (131072 bytes)
/// - `settings`: KZG settings
///
/// # Returns
/// - `Ok(ZG1)`: commitment
/// - `Err(String)`: error message
pub fn blob_bytes_to_commitment(
    blob_bytes: &[u8; 131072],
    settings: &KZGSettings,
) -> Result<ZG1, String> {
    let blob = bytes_to_blob(blob_bytes)?;
    blob_to_commitment(&blob, settings)
}

/// Compute blob KZG proof (simplified version)
///
/// # Arguments
/// - `blob`: blob as field elements
/// - `commitment`: KZG commitment
/// - `settings`: KZG settings
///
/// # Returns
/// - `Ok(ZG1)`: proof
/// - `Err(String)`: error message
pub fn compute_proof(
    blob: &[ZFr],
    commitment: &ZG1,
    settings: &KZGSettings,
) -> Result<ZG1, String> {
    compute_blob_kzg_proof_rust::<
        ZFr,
        ZG1,
        ZG2,
        FFTSettings,
        PolyData,
        KZGSettings,
        ZFp,
        ZG1Affine,
        ZG1ProjAddAffine,
    >(blob, commitment, settings)
}

/// Verify blob KZG proof (simplified version)
///
/// # Arguments
/// - `blob`: blob as field elements
/// - `commitment`: KZG commitment
/// - `proof`: KZG proof
/// - `settings`: KZG settings
///
/// # Returns
/// - `Ok(bool)`: verification result
/// - `Err(String)`: error message
pub fn verify_proof(
    blob: &[ZFr],
    commitment: &ZG1,
    proof: &ZG1,
    settings: &KZGSettings,
) -> Result<bool, String> {
    verify_blob_kzg_proof_rust::<
        ZFr,
        ZG1,
        ZG2,
        FFTSettings,
        PolyData,
        KZGSettings,
        ZFp,
        ZG1Affine,
        ZG1ProjAddAffine,
    >(blob, commitment, proof, settings)
}

#[cfg(test)]
mod tests {
    use super::*;
    // use crate::eip_4844::load_trusted_setup_filename_rust;
    use kzg::eip_4844::{bytes_to_blob, load_trusted_setup_rust, load_trusted_setup_string};
    use kzg::G1;
    use std::fs;
    use std::io::Read;
    use std::path::PathBuf;

    fn get_trusted_setup_path() -> String {
        // trusted_setup.txt is located at kzg-bench/src/trusted_setup.txt
        // Relative path when running from zkcrypto/src
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("..");
        path.push("kzg-bench");
        path.push("src");
        path.push("trusted_setup.txt");
        path.to_string_lossy().to_string()
    }

    fn perform_commit_proof_verify(
        blob_bytes: &[u8; 131072],
        settings: &KZGSettings,
    ) -> Result<(ZG1, ZG1), String> {
        // 1. Compute commitment
        let commitment = blob_bytes_to_commitment(blob_bytes, settings)?;

        // 2. Convert blob to field elements
        let blob = bytes_to_blob(blob_bytes)?;

        // 3. Compute proof
        let proof = compute_proof(&blob, &commitment, settings)?;

        // 4. Verify proof
        let verified = verify_proof(&blob, &commitment, &proof, settings)?;
        assert!(verified, "Proof verification failed");

        Ok((commitment, proof))
    }

    pub fn load_trusted_setup_filename_rust(filepath: &str) -> Result<KZGSettings, String> {
        let mut file =
            std::fs::File::open(filepath).map_err(|_| "Unable to open file".to_string())?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(|_| "Unable to read file".to_string())?;

        let start = std::time::Instant::now();

        let (g1_monomial_bytes, g1_lagrange_bytes, g2_monomial_bytes) =
            load_trusted_setup_string(&contents)?;
        let load_time = std::time::Instant::now().duration_since(start);
        println!(
            "✓ load_trusted_setup_string trusted setup in {:.2}s",
            load_time.as_secs_f64()
        );

        let start = std::time::Instant::now();
        let setting =
            load_trusted_setup_rust(&g1_monomial_bytes, &g1_lagrange_bytes, &g2_monomial_bytes)?;
        let load_time = std::time::Instant::now().duration_since(start);
        println!(
            "✓ load_trusted_setup_rust trusted setup in {:.2}s",
            load_time.as_secs_f64()
        );
        Ok(setting)
    }

    #[test]
    fn test_import_kzg_settings() {
        // 1. Load Ethereum's KZG settings
        // Note: Initial loading can be very slow (may take tens of seconds to minutes) because it requires:
        // - Parsing text file (800KB+)
        // - Deserializing 4096 G1 points and 65 G2 points
        // - Computing FFT settings
        // - Generating precomputation tables (if enabled)
        // This is why serialization is valuable - it avoids repeating these expensive computations!
        let trusted_setup_path = get_trusted_setup_path();
        println!(
            "Loading trusted setup from: {} (this may take a while...)",
            trusted_setup_path
        );
        let start = std::time::Instant::now();
        let _ = load_trusted_setup_filename_rust(&trusted_setup_path)
            .expect("Failed to load trusted setup");
        let load_time = start.elapsed();
        println!(
            "✓ test_import_kzg_settings trusted setup in {:.2}s",
            load_time.as_secs_f64()
        );
    }

    #[test]
    fn test_serialize_and_deserialize_kzg_settings() {
        // 1. Load Ethereum's KZG settings
        // Note: Initial loading can be very slow (may take tens of seconds to minutes) because it requires:
        // - Parsing text file (800KB+)
        // - Deserializing 4096 G1 points and 65 G2 points
        // - Computing FFT settings
        // - Generating precomputation tables (if enabled)
        // This is why serialization is valuable - it avoids repeating these expensive computations!
        let trusted_setup_path = get_trusted_setup_path();
        println!(
            "Loading trusted setup from: {} (this may take a while...)",
            trusted_setup_path
        );
        let start = std::time::Instant::now();
        let settings = load_trusted_setup_filename_rust(&trusted_setup_path)
            .expect("Failed to load trusted setup");
        let load_time = start.elapsed();
        println!("✓ Loaded trusted setup in {:.2}s", load_time.as_secs_f64());

        // 2. Prepare test blob data
        let blob_bytes = [0u8; 131072]; // BYTES_PER_BLOB = 131072

        // 3. Perform commit/proof/verify with original settings
        println!("Performing commit/proof/verify with original settings...");
        let (commitment1, proof1) = perform_commit_proof_verify(&blob_bytes, &settings)
            .expect("Failed to perform commit/proof/verify with original settings");

        println!("Original commitment: {:?}", commitment1.to_bytes());
        println!("Original proof: {:?}", proof1.to_bytes());

        // 4. Serialize KZG settings to binary file
        // Serialization is fast (a few milliseconds) because it's just memory copying
        let binary_file = "kzg_settings.bin";
        println!("Serializing KZG settings to binary file: {}", binary_file);
        let start = std::time::Instant::now();
        let serialized = bincode::serialize(&settings).expect("Failed to serialize KZGSettings");
        fs::write(binary_file, &serialized).expect("Failed to write binary file");
        let serialize_time = start.elapsed();
        println!(
            "✓ Serialized in {:.2}ms, size: {} bytes ({:.2} MB)",
            serialize_time.as_secs_f64() * 1000.0,
            serialized.len(),
            serialized.len() as f64 / 1024.0 / 1024.0
        );

        // 5. Load KZG settings from binary file
        // Deserialization is also fast (a few seconds), much faster than loading from text file!
        println!("Loading KZG settings from binary file: {}", binary_file);
        let start = std::time::Instant::now();
        let binary_data = fs::read(binary_file).expect("Failed to read binary file");
        let deserialized_settings: KZGSettings = bincode::deserialize(&binary_data)
            .expect("Failed to deserialize KZGSettings from binary");
        let deserialize_time = start.elapsed();
        println!(
            "✓ Deserialized in {:.2}s (much faster than loading from text file!)",
            deserialize_time.as_secs_f64()
        );

        // 6. Perform the same commit/proof/verify with deserialized settings
        println!("Performing commit/proof/verify with deserialized settings...");
        let (commitment2, proof2) =
            perform_commit_proof_verify(&blob_bytes, &deserialized_settings)
                .expect("Failed to perform commit/proof/verify with deserialized settings");

        println!("Deserialized commitment: {:?}", commitment2.to_bytes());
        println!("Deserialized proof: {:?}", proof2.to_bytes());

        // 7. Verify that both results are identical
        assert_eq!(
            commitment1.to_bytes(),
            commitment2.to_bytes(),
            "Commitments should be identical"
        );
        assert_eq!(
            proof1.to_bytes(),
            proof2.to_bytes(),
            "Proofs should be identical"
        );

        println!("✓ All tests passed! Commitments and proofs match.");
    }
}
