#include "psa_se05x_wrapper.h"
#include "SE05X.h"
#include "se05x_types.h"

extern SE05XClass SE05X;

static inline int psa_to_se_id(psa_key_handle_t handle) {
    return (int)handle;
}

// Initialization

extern "C" psa_status_t psa_se05x_init(void) {
    if (SE05X.begin() != 1)
        return PSA_ERROR_HARDWARE_FAILURE;
    return PSA_SUCCESS;
}

// Random number generation

extern "C" psa_status_t psa_se05x_generate_random(uint8_t *output, size_t output_size) {
    if (SE05X.random(output, output_size) != 1)
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
            ret = SE05X.SHA256(input, input_length, hash, hash_size, hash_length);
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
    
    if (SE05X.AES_ECB_encrypt(psa_to_se_id(key_handle), input, input_length, output, output_length) != 1)
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
    
    if (SE05X.AES_ECB_decrypt(psa_to_se_id(key_handle), input, input_length, output, output_length) != 1)
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
    
    if (SE05X.Sign(psa_to_se_id(key_handle), hash, hash_length, signature, signature_size, &der_len) != 1)
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
    if (SE05X.Verify(psa_to_se_id(key_handle), hash, hash_length, signature, signature_length) != 1)
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
            ret = SE05X.SignRSA(psa_to_se_id(key_handle), hash, hash_length, signature, signature_size, signature_length);
            break;
        }
        
        case PSA_ALG_RSA_PSS(PSA_ALG_SHA_256): {
            uint8_t encoded[256];
            size_t encoded_len = sizeof(encoded);
            
            ret = SE05X.emsa_pss_encode(
                (uint8_t*)hash,
                hash_length,
                encoded,
                &encoded_len,
                SE05x_RSASignatureAlgo_t::kSE05x_RSASignatureAlgo_SHA256_PKCS1_PSS,
                SE05x_RSABitLength_t::kSE05x_RSABitLength_2048);
            
            if (ret != 1)
                return PSA_ERROR_HARDWARE_FAILURE;
            
            // Then sign the encoded hash
            ret = SE05X.SignRSA(psa_to_se_id(key_handle), encoded, encoded_len,
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
            ret = SE05X.VerifyRSASSA_PKCS1(psa_to_se_id(key_handle), hash, hash_length, signature, signature_length);
            break;
            
        case PSA_ALG_RSA_PSS(PSA_ALG_SHA_256):
            ret = SE05X.VerifyRSASSA_PSS(psa_to_se_id(key_handle), (uint8_t*)hash, hash_length, signature, signature_length);
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
        if (SE05X.writeAESKey(se_id, data, data_length) != 1)
            return PSA_ERROR_HARDWARE_FAILURE;
            
    } else if (PSA_KEY_TYPE_IS_ECC(key_type)) {
        if (SE05X.importPublicKey(se_id, data, data_length) != 1)
            return PSA_ERROR_HARDWARE_FAILURE;
            
    } else if (PSA_KEY_TYPE_IS_RSA(key_type)) {
        if (SE05X.writeRSAKey(
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
    int se_id = *key_handle;
    psa_key_type_t key_type = psa_get_key_type(attributes);
    
    if (key_type == PSA_KEY_TYPE_AES) {
        uint8_t key[32];
        size_t key_size = psa_get_key_bits(attributes) / 8;
        
        if (psa_se05x_generate_random(key, key_size) != PSA_SUCCESS)
            return PSA_ERROR_HARDWARE_FAILURE;
            
        return psa_se05x_import_key(attributes, key, key_size, key_handle);
        
    } else if (PSA_KEY_TYPE_IS_ECC(key_type)) {
        if (key_type == PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1)) {
            uint16_t key_bits = psa_get_key_bits(attributes);
            if (key_bits != 256){
                return PSA_ERROR_NOT_SUPPORTED;
            }
            uint8_t psa_pubkey[64];

            if (SE05X.generatePrivateKey(se_id, psa_pubkey) != 1)
                return PSA_ERROR_HARDWARE_FAILURE;
        }
        
    } else if (PSA_KEY_TYPE_IS_RSA(key_type)) {
        // Allocate buffers for modulus and exponent output
        uint8_t modulus[512];
        size_t mod_len = sizeof(modulus);
        uint8_t exponent[8];
        size_t exp_len = sizeof(exponent);
        
        uint16_t key_bits = psa_get_key_bits(attributes);
        
        if (SE05X.generatePrivateRSAKey(se_id, modulus, &mod_len, exponent, &exp_len, key_bits) != 1)
            return PSA_ERROR_HARDWARE_FAILURE;
            
    } else {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    
    return PSA_SUCCESS;
}

extern "C" psa_status_t psa_se05x_destroy_key(psa_key_handle_t key_handle) {
    if (SE05X.deleteBinaryObject(psa_to_se_id(key_handle)) != 1)
        return PSA_ERROR_HARDWARE_FAILURE;
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