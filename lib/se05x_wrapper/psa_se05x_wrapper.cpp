#include "psa_se05x_wrapper.h"
#include "se05x_extended.h"

se05x_extended SE05X_ext;

static inline int psa_to_se_id(psa_key_handle_t handle) {
    return (int)handle;
}

// Initialization

extern "C" psa_status_t psa_se05x_init(void) {
    if (SE05X_ext.begin() != 1)
        return PSA_ERROR_HARDWARE_FAILURE;
    return PSA_SUCCESS;
}

// Random number generation

extern "C" psa_status_t psa_se05x_generate_random(uint8_t *output, size_t output_size) {
    if (SE05X_ext.random(output, output_size) != 1)
        return PSA_ERROR_HARDWARE_FAILURE;
    return PSA_SUCCESS;
}

// Hash computation

extern "C" psa_status_t psa_se05x_hash_compute(
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *hash,
    size_t hash_size,
    size_t *hash_length)
{
    int ret = 0;
    switch (alg) {
        case PSA_ALG_SHA_256:
            ret = SE05X_ext.SHA256(input, input_length, hash, hash_size, hash_length);
            break;
        default:
            return PSA_ERROR_NOT_SUPPORTED;
    }
    return ret == 1 ? PSA_SUCCESS : PSA_ERROR_HARDWARE_FAILURE;
}

// AES encryption and decryption

extern "C" psa_status_t psa_se05x_aes_encrypt(
    psa_key_handle_t key_handle,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length)
{
    if (!input || !output || !output_length)
        return PSA_ERROR_INVALID_ARGUMENT;
        
    if ((input_length % 16 != 0) || (input_length > output_size))
        return PSA_ERROR_INVALID_ARGUMENT;
    
    // Initialize output length
    *output_length = output_size;
    
    if (SE05X_ext.AES_ECB_encrypt(psa_to_se_id(key_handle), input, input_length, output, output_length) != 1)
        return PSA_ERROR_HARDWARE_FAILURE;
    
    return PSA_SUCCESS;
}

extern "C" psa_status_t psa_se05x_aes_decrypt(
    psa_key_handle_t key_handle,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length)
{
    if (!input || !output || !output_length)
        return PSA_ERROR_INVALID_ARGUMENT;
        
    if ((input_length % 16 != 0) || (input_length > output_size))
        return PSA_ERROR_INVALID_ARGUMENT;
    
    // Initialize output length
    *output_length = output_size;
    
    if (SE05X_ext.AES_ECB_decrypt(psa_to_se_id(key_handle), input, input_length, output, output_length) != 1)
        return PSA_ERROR_HARDWARE_FAILURE;
    
    return PSA_SUCCESS;
}

// ECDSA signing and verification

extern "C" psa_status_t psa_se05x_ecdsa_sign(
    psa_key_handle_t key_handle,
    psa_algorithm_t alg,
    const uint8_t *hash,
    size_t hash_length,
    uint8_t *signature,
    size_t signature_size,
    size_t *signature_length)
{
    size_t der_len = 0;
    
    if (SE05X_ext.Sign(psa_to_se_id(key_handle), hash, hash_length, signature, signature_size, &der_len) != 1)
        return PSA_ERROR_HARDWARE_FAILURE;
    
    if (signature_length) {
        *signature_length = der_len;
    }
    
    return PSA_SUCCESS;
}

extern "C" psa_status_t psa_se05x_ecdsa_verify(
    psa_key_handle_t key_handle,
    psa_algorithm_t alg,
    const uint8_t *hash,
    size_t hash_length,
    const uint8_t *signature,
    size_t signature_length)
{
    if (SE05X_ext.Verify(psa_to_se_id(key_handle), hash, hash_length, signature, signature_length) != 1)
        return PSA_ERROR_INVALID_SIGNATURE;
    
    return PSA_SUCCESS;
}

// RSA signing and verification

extern "C" psa_status_t psa_se05x_rsa_sign(
    psa_key_handle_t key_handle,
    psa_algorithm_t alg,
    const uint8_t *hash,
    size_t hash_length,
    uint8_t *signature,
    size_t signature_size,
    size_t *signature_length)
{
    int ret = 0;
    
    switch (alg) {
        case PSA_ALG_RSA_PKCS1V15_SIGN_RAW:
        case PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256): {
            ret = SE05X_ext.SignRSA(psa_to_se_id(key_handle), hash, hash_length, signature, signature_size, signature_length);
            break;
        }
        
        case PSA_ALG_RSA_PSS(PSA_ALG_SHA_256): {
            uint8_t encoded[256];
            size_t encoded_len = sizeof(encoded);
            
            ret = SE05X_ext.emsa_pss_encode(
                (uint8_t*)hash,
                hash_length,
                encoded,
                &encoded_len,
                SE05x_RSASignatureAlgo_t::kSE05x_RSASignatureAlgo_SHA256_PKCS1_PSS,
                SE05x_RSABitLength_t::kSE05x_RSABitLength_2048);
            
            if (ret != 1)
                return PSA_ERROR_HARDWARE_FAILURE;
            
            // Then sign the encoded hash
            ret = SE05X_ext.SignRSA(psa_to_se_id(key_handle), encoded, encoded_len,
                                signature, signature_size, signature_length);
            break;
        }
        
        default:
            return PSA_ERROR_NOT_SUPPORTED;
    }
    
    return ret == 1 ? PSA_SUCCESS : PSA_ERROR_HARDWARE_FAILURE;
}

extern "C" psa_status_t psa_se05x_rsa_verify(
    psa_key_handle_t key_handle,
    psa_algorithm_t alg,
    const uint8_t *hash,
    size_t hash_length,
    const uint8_t *signature,
    size_t signature_length)
{
    int ret = 0;
    
    switch (alg) {
        case PSA_ALG_RSA_PKCS1V15_SIGN_RAW:
        case PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256):
            ret = SE05X_ext.VerifyRSASSA_PKCS1(psa_to_se_id(key_handle), hash, hash_length, signature, signature_length);
            break;
            
        case PSA_ALG_RSA_PSS(PSA_ALG_SHA_256):
            ret = SE05X_ext.VerifyRSASSA_PSS(psa_to_se_id(key_handle), (uint8_t*)hash, hash_length, signature, signature_length);
            break;
            
        default:
            return PSA_ERROR_NOT_SUPPORTED;
    }
    
    return ret == 1 ? PSA_SUCCESS : PSA_ERROR_INVALID_SIGNATURE;
}

// Key management operations

extern "C" psa_status_t psa_se05x_import_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data,
    size_t data_length,
    psa_key_handle_t *key_handle)
{
    int se_id = *key_handle;
    psa_key_type_t key_type = psa_get_key_type(attributes);
    
    if (key_type == PSA_KEY_TYPE_AES) {
        if (SE05X_ext.writeAESKey(se_id, data, data_length) != 1)
            return PSA_ERROR_HARDWARE_FAILURE;
            
    } else if (PSA_KEY_TYPE_IS_ECC(key_type)) {
        if (SE05X_ext.importPublicKey(se_id, data, data_length) != 1)
            return PSA_ERROR_HARDWARE_FAILURE;
            
    } else if (PSA_KEY_TYPE_IS_RSA(key_type)) {
        if (SE05X_ext.writeRSAKey(
                se_id,
                SE05x_RSABitLength_t::kSE05x_RSABitLength_2048,
                nullptr, 0,
                nullptr, 0,
                nullptr, 0,
                nullptr, 0,
                nullptr, 0,
                nullptr, 0,
                data, data_length,
                nullptr, 0,
                SE05x_RSAKeyFormat_t::kSE05x_RSAKeyFormat_RAW,
                false,
                kSE05x_KeyPart_Public,
                nullptr) != 1)
            return PSA_ERROR_HARDWARE_FAILURE;
            
    } else {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    
    return PSA_SUCCESS;
}

extern "C" psa_status_t psa_se05x_generate_key(
    const psa_key_attributes_t *attributes,
    psa_key_handle_t *key_handle)
{
    int se_id = (int)psa_get_key_id(attributes);
    psa_key_type_t key_type = psa_get_key_type(attributes);
    uint16_t key_bits = psa_get_key_bits(attributes);

    Serial.print("se_id="); Serial.println(se_id);
    Serial.print("key_type=0x"); Serial.println(key_type, HEX);
    Serial.print("key_bits="); Serial.println(key_bits);
    Serial.print("lifetime=0x"); Serial.println(psa_get_key_lifetime(attributes), HEX);

    if (key_type == PSA_KEY_TYPE_AES) {
        Serial.println("AES branch");
        uint8_t key[32];
        size_t key_size = psa_get_key_bits(attributes) / 8;
        if (psa_se05x_generate_random(key, key_size) != PSA_SUCCESS)
            return PSA_ERROR_HARDWARE_FAILURE;
        return psa_se05x_import_key(attributes, key, key_size, key_handle);

    } else if (PSA_KEY_TYPE_IS_ECC(key_type)) {
        Serial.println("ECC branch");
        if (key_type == PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1)) {
            Serial.println("ECC SECP256R1 branch");
            if (key_bits != 256){
                Serial.println("bits != 256");
                return PSA_ERROR_NOT_SUPPORTED;
            }
            uint8_t psa_pubkey[64];
            int ret = SE05X_ext.generatePrivateKey(se_id, psa_pubkey);
            Serial.print("SE05X_ext.generatePrivateKey ret="); Serial.println(ret);
            if (ret != 1)
                return PSA_ERROR_HARDWARE_FAILURE;
        } else {
            Serial.println("Unsupported ECC curve");
            Serial.println(key_type, HEX);
            return PSA_ERROR_NOT_SUPPORTED;
        }

    } else if (PSA_KEY_TYPE_IS_RSA(key_type)) {
        Serial.println("RSA branch");
        uint8_t modulus[512];
        size_t mod_len = sizeof(modulus);
        uint8_t exponent[8];
        size_t exp_len = sizeof(exponent);
        uint16_t key_bits = psa_get_key_bits(attributes);
        int ret = SE05X_ext.generatePrivateRSAKey(se_id, modulus, &mod_len, exponent, &exp_len, key_bits);
        if (ret != 1){
            Serial.print("SE05X_ext.generatePrivateRSAKey ret="); Serial.println(ret);
            return PSA_ERROR_HARDWARE_FAILURE;
        }

    } else {
        Serial.println("Unsupported ");
        Serial.println(key_type, HEX);
        return PSA_ERROR_NOT_SUPPORTED;
    }

    *key_handle = (psa_key_handle_t)se_id;  
    return PSA_SUCCESS;
}

extern "C" psa_status_t psa_se05x_destroy_key(psa_key_handle_t key_handle) {
    if (SE05X_ext.deleteBinaryObject(psa_to_se_id(key_handle)) != 1)
        return PSA_ERROR_HARDWARE_FAILURE;
    return PSA_SUCCESS;
}

extern "C" psa_status_t psa_se05x_key_agreement(
    psa_algorithm_t alg,
    psa_key_handle_t private_key,
    const uint8_t *peer_key,
    size_t peer_key_length,
    uint8_t *shared_secret,
    size_t shared_secret_size,
    size_t *shared_secret_length)
{
    if (!PSA_ALG_IS_ECDH(alg))
        return PSA_ERROR_NOT_SUPPORTED;
    if (!peer_key || !shared_secret || !shared_secret_length)
        return PSA_ERROR_INVALID_ARGUMENT;

    const uint8_t *ec_point = peer_key;
    size_t ec_point_len = peer_key_length;

    // Strip SPKI/DER wrapper if present (P-256 SPKI = 91 bytes)
    // Raw point starts at offset 26: 04 || X || Y (65 bytes)
    uint8_t tmp_key[65];
    if (peer_key_length == 91 && peer_key[0] == 0x30) {
        // offset 26 = start of 0x04 uncompressed point
        ec_point = peer_key + 26;
        ec_point_len = 65;
    }
    else if (peer_key_length == 64) {
        // Raw X||Y without 0x04 prefix — add it
        tmp_key[0] = 0x04;
        memcpy(&tmp_key[1], peer_key, 64);
        ec_point = tmp_key;
        ec_point_len = 65;
    }
    // else assume already 65-byte 04||X||Y

    size_t out_len = shared_secret_size;
    if (SE05X_ext.ECDH(psa_to_se_id(private_key),
                   ec_point, ec_point_len,
                   shared_secret, &out_len) != 1)
    {
        return PSA_ERROR_HARDWARE_FAILURE;
    }

    *shared_secret_length = out_len;
    return PSA_SUCCESS;
}


// Standard PSA API function implementations

extern "C" psa_status_t psa_crypto_init(void) {
    return psa_se05x_init();
}

extern "C" psa_status_t psa_generate_key(
    const psa_key_attributes_t *attr,
    psa_key_handle_t *key_handle)
{
    Serial.print("[psa_generate_key wrapper] type=0x");
    Serial.println(psa_get_key_type(attr), HEX);
    return psa_se05x_generate_key(attr, key_handle);
}

extern "C" psa_status_t psa_destroy_key(psa_key_handle_t key_handle) {
    return psa_se05x_destroy_key(key_handle);
}

extern "C" psa_status_t psa_import_key(
    const psa_key_attributes_t *attr,
    const uint8_t *data,
    size_t data_len,
    psa_key_handle_t *key_handle)
{
    return psa_se05x_import_key(attr, data, data_len, key_handle);
}

extern "C" psa_status_t psa_generate_random(uint8_t *output, size_t output_size) {
    Serial.print("Generating ");Serial.print(output_size);
    Serial.println(" random bytes for mbedTLS...");
    return psa_se05x_generate_random(output, output_size);
}

extern "C" psa_status_t psa_hash_compute(
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *hash,
    size_t hash_size,
    size_t *hash_length)
{
    return psa_se05x_hash_compute(alg, input, input_length, hash, hash_size, hash_length);
}

extern "C" psa_status_t psa_sign_hash(
    psa_key_id_t key,
    psa_algorithm_t alg,
    const uint8_t *hash,
    size_t hash_length,
    uint8_t *signature,
    size_t signature_size,
    size_t *signature_length)
{
    if (PSA_ALG_IS_ECDSA(alg)) {
        return psa_se05x_ecdsa_sign(key, alg, hash, hash_length, signature, signature_size, signature_length);
    } else if (PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg) || PSA_ALG_IS_RSA_PSS(alg)) {
        return psa_se05x_rsa_sign(key, alg, hash, hash_length, signature, signature_size, signature_length);
    }
    
    return PSA_ERROR_NOT_SUPPORTED;
}

extern "C" psa_status_t psa_verify_hash(
    psa_key_id_t key,
    psa_algorithm_t alg,
    const uint8_t *hash,
    size_t hash_length,
    const uint8_t *signature,
    size_t signature_length)
{
    if (PSA_ALG_IS_ECDSA(alg)) {
        return psa_se05x_ecdsa_verify(key, alg, hash, hash_length, signature, signature_length);
    } else if (PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg) || PSA_ALG_IS_RSA_PSS(alg)) {
        return psa_se05x_rsa_verify(key, alg, hash, hash_length, signature, signature_length);
    }
    
    return PSA_ERROR_NOT_SUPPORTED;
}

extern "C" psa_status_t psa_export_public_key(
    psa_key_id_t key,
    uint8_t *data,
    size_t data_size,
    size_t *data_length)
{
    if (!SE05X.existsBinaryObject(psa_to_se_id(key))) {
        Serial.println("Key does not exist in SE05X");
        return PSA_ERROR_INVALID_HANDLE;
    }
    
    size_t pubkey_len = 0;
    int result = SE05X.generatePublicKey(psa_to_se_id(key), data, data_size, &pubkey_len);
    
    if (result != 1) {
        Serial.print("SE05X.generatePublicKey returned: ");
        Serial.println(result);
        return PSA_ERROR_HARDWARE_FAILURE;
    }
    
    if (data_length) {
        *data_length = pubkey_len;
    }
    
    return PSA_SUCCESS;
}

extern "C" psa_status_t psa_raw_key_agreement(
    psa_algorithm_t alg,
    psa_key_id_t private_key,
    const uint8_t *peer_key,
    size_t peer_key_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length)
{
    Serial.println("psa_raw_key_agreement called");
    return psa_se05x_key_agreement(
        alg,
        private_key,
        peer_key,
        peer_key_length,
        output,
        output_size,
        output_length);
}

// Add these stubs with logging to your wrapper:

extern "C" psa_status_t psa_key_derivation_setup(
    psa_key_derivation_operation_t *operation,
    psa_algorithm_t alg) {
    Serial.println("[WRAPPER] psa_key_derivation_setup");
    return PSA_ERROR_NOT_SUPPORTED; // Force fallback to see if TLS still works
}

// At the top of psa_se05x_wrapper.cpp, before your implementations:
extern "C" psa_status_t psa_key_derivation_key_agreement_fallback(
    psa_key_derivation_operation_t *operation,
    psa_key_derivation_step_t step,
    mbedtls_svc_key_id_t private_key,
    const uint8_t *peer_key,
    size_t peer_key_length);

extern "C" psa_status_t psa_key_derivation_key_agreement(
    psa_key_derivation_operation_t *operation,
    psa_key_derivation_step_t step,
    mbedtls_svc_key_id_t private_key,
    const uint8_t *peer_key,
    size_t peer_key_length)
{
    Serial.println(">>> [SE05X] psa_key_derivation_key_agreement INTERCEPTED <<<");
    Serial.print("    step=0x"); Serial.println(step, HEX);
    Serial.print("    key_id="); Serial.println(PSA_KEY_ID_NULL); // Debug
    
    // For now: delegate to software fallback
    // (Implement full SE05X offload later if needed)
    return psa_key_derivation_key_agreement_fallback(
        operation, step, private_key, peer_key, peer_key_length);
}