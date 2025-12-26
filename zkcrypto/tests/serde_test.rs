#[cfg(test)]
#[cfg(feature = "serde")]
mod tests {
    use rust_kzg_zkcrypto::eip_4844::load_trusted_setup_filename_rust;
    use rust_kzg_zkcrypto::kzg_proofs::KZGSettings;
    use kzg::eip_4844::{blob_to_kzg_commitment_rust, verify_blob_kzg_proof_rust, bytes_to_blob, compute_blob_kzg_proof_rust};
    use rust_kzg_zkcrypto::kzg_types::{ZFr, ZG1, ZG2};
    use rust_kzg_zkcrypto::poly::PolyData;
    use rust_kzg_zkcrypto::kzg_proofs::FFTSettings;
    use rust_kzg_zkcrypto::kzg_types::{ZFp, ZG1Affine, ZG1ProjAddAffine};
    use kzg::G1;

    #[test]
    fn test_kzg_settings_serialization_json() {
        // Load trusted setup
        let settings = load_trusted_setup_filename_rust("../../src/trusted_setup.txt")
            .expect("Failed to load trusted setup");

        // Serialize to JSON
        let serialized = serde_json::to_string(&settings)
            .expect("Failed to serialize KZGSettings");

        // Deserialize from JSON
        let deserialized: KZGSettings = serde_json::from_str(&serialized)
            .expect("Failed to deserialize KZGSettings");

        verify_settings_work(&settings, &deserialized);
    }

    #[cfg(feature = "bincode")]
    #[test]
    fn test_kzg_settings_serialization_bincode() {
        // Load trusted setup
        let settings = load_trusted_setup_filename_rust("../../src/trusted_setup.txt")
            .expect("Failed to load trusted setup");

        // Serialize to bincode (more efficient than JSON)
        let serialized = bincode::serialize(&settings)
            .expect("Failed to serialize KZGSettings with bincode");

        // Deserialize from bincode
        let deserialized: KZGSettings = bincode::deserialize(&serialized)
            .expect("Failed to deserialize KZGSettings from bincode");

        verify_settings_work(&settings, &deserialized);
    }

    fn verify_settings_work(settings: &KZGSettings, deserialized: &KZGSettings) {

        // Verify that deserialized settings work correctly
        // Create a test blob
        let blob_bytes = [0u8; 131072]; // BYTES_PER_BLOB = 131072
        let blob = bytes_to_blob(&blob_bytes).expect("Failed to convert blob");

        // Compute commitment with original settings
        let commitment1 = blob_to_kzg_commitment_rust::<
            ZFr,
            ZG1,
            ZG2,
            FFTSettings,
            PolyData,
            KZGSettings,
            ZFp,
            ZG1Affine,
            ZG1ProjAddAffine,
        >(&blob, &settings).expect("Failed to compute commitment");

        // Compute commitment with deserialized settings
        let commitment2 = blob_to_kzg_commitment_rust::<
            ZFr,
            ZG1,
            ZG2,
            FFTSettings,
            PolyData,
            KZGSettings,
            ZFp,
            ZG1Affine,
            ZG1ProjAddAffine,
        >(&blob, &deserialized).expect("Failed to compute commitment with deserialized settings");

        // Verify commitments are the same
        assert_eq!(commitment1.to_bytes(), commitment2.to_bytes());

        // Test verify function
        let proof = compute_blob_kzg_proof_rust::<
            ZFr,
            ZG1,
            ZG2,
            FFTSettings,
            PolyData,
            KZGSettings,
            ZFp,
            ZG1Affine,
            ZG1ProjAddAffine,
        >(&blob, &commitment1, &deserialized).expect("Failed to compute proof");

        let verified = verify_blob_kzg_proof_rust::<
            ZFr,
            ZG1,
            ZG2,
            FFTSettings,
            PolyData,
            KZGSettings,
            ZFp,
            ZG1Affine,
            ZG1ProjAddAffine,
        >(&blob, &commitment1, &proof, &deserialized).expect("Failed to verify proof");

        assert!(verified, "Proof verification failed");
    }
}

