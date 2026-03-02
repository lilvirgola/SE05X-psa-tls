#include "psa_se05x_wrapper.h"
#include "SE05X.h"
#include "se05x_types.h"

extern SE05XClass SE05X;

// Map PSA handle to SE05X object ID
static inline int psa_to_se_id(psa_key_handle_t handle) { return (int)handle; }

// ---------------- Initialization ----------------
extern "C" psa_status_t psa_se05x_init(void) {
    if (SE05X.begin() != 1)
        return PSA_ERROR_HARDWARE_FAILURE;
    return PSA_SUCCESS;
}

// ---------------- Random ----------------
extern "C" psa_status_t psa_se05x_generate_random(uint8_t *output, size_t output_size) {
    if (SE05X.random(output, output_size) != 1)
        return PSA_ERROR_HARDWARE_FAILURE;
    return PSA_SUCCESS;
}

// ---------------- One-shot hash ----------------
extern "C" psa_status_t psa_se05x_hash_compute(psa_algorithm_t alg,
                                               const uint8_t *input, size_t input_length,
                                               uint8_t *hash, size_t hash_size, size_t *hash_length) {
    int ret = 0;
    switch (alg) {
        case PSA_ALG_SHA_256: ret = SE05X.SHA256(input, input_length, hash, hash_size, hash_length); break;
        default: return PSA_ERROR_NOT_SUPPORTED;
    }
    return ret == 1 ? PSA_SUCCESS : PSA_ERROR_HARDWARE_FAILURE;
}

// ---------------- AES ECB ----------------
extern "C" psa_status_t psa_se05x_aes_encrypt(psa_key_handle_t key_handle,
                                              psa_algorithm_t alg,
                                              const uint8_t *input, size_t input_length,
                                              uint8_t *output, size_t output_size,
                                              size_t *output_length) {
    if ((input_length % 16 != 0) || (input_length > output_size))
        return PSA_ERROR_INVALID_ARGUMENT;
    if (SE05X.AES_ECB_encrypt(psa_to_se_id(key_handle), input, input_length, output, output_length) != 1)
        return PSA_ERROR_HARDWARE_FAILURE;
    return PSA_SUCCESS;
}

extern "C" psa_status_t psa_se05x_aes_decrypt(psa_key_handle_t key_handle,
                                              psa_algorithm_t alg,
                                              const uint8_t *input, size_t input_length,
                                              uint8_t *output, size_t output_size,
                                              size_t *output_length) {
    if ((input_length % 16 != 0) || (input_length > output_size))
        return PSA_ERROR_INVALID_ARGUMENT;
    if (SE05X.AES_ECB_decrypt(psa_to_se_id(key_handle), input, input_length, output, output_length) != 1)
        return PSA_ERROR_HARDWARE_FAILURE;
    return PSA_SUCCESS;
}

// ---------------- ECC Sign/Verify ----------------
extern "C" psa_status_t psa_se05x_ecdsa_sign(psa_key_handle_t key_handle,
                                             psa_algorithm_t alg,
                                             const uint8_t *hash, size_t hash_length,
                                             uint8_t *signature, size_t signature_size,
                                             size_t *signature_length) {
    uint8_t der_sig[80];
    size_t der_len = sizeof(der_sig);
    if (SE05X.Sign(psa_to_se_id(key_handle), hash, hash_length, der_sig, sizeof(der_sig), &der_len) != 1)
        return PSA_ERROR_HARDWARE_FAILURE;
    size_t raw_len = signature_size;
    *signature_length = raw_len;
    return PSA_SUCCESS;
}

extern "C" psa_status_t psa_se05x_ecdsa_verify(psa_key_handle_t key_handle,
                                               psa_algorithm_t alg,
                                               const uint8_t *hash, size_t hash_length,
                                               const uint8_t *signature, size_t signature_length) {
    if (SE05X.ecdsaVerify(hash, signature, nullptr) != 1)
        return PSA_ERROR_INVALID_SIGNATURE;
    return PSA_SUCCESS;
}

// ---------------- RSA Sign/Verify/Encrypt/Decrypt ----------------
extern "C" psa_status_t psa_se05x_rsa_sign(psa_key_handle_t key_handle,
                                           psa_algorithm_t alg,
                                           const uint8_t *hash, size_t hash_length,
                                           uint8_t *signature, size_t signature_size,
                                           size_t *signature_length) {
    int ret = 0;
    switch (alg) {
        case PSA_ALG_RSA_PKCS1V15_SIGN_RAW:
        case PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256):
            ret = SE05X.SignRSA(psa_to_se_id(key_handle), hash, hash_length, signature, signature_size, signature_length);
            break;
        case PSA_ALG_RSA_PSS(PSA_ALG_SHA_256):
            ret = SE05X.emsa_pss_encode((uint8_t*)hash, hash_length, signature, signature_length,
                                        SE05x_RSASignatureAlgo_t::kSE05x_RSASignatureAlgo_SHA256_PKCS1_PSS, SE05x_RSABitLength_t::kSE05x_RSABitLength_2048);
            break;
        default: return PSA_ERROR_NOT_SUPPORTED;
    }
    return ret == 1 ? PSA_SUCCESS : PSA_ERROR_HARDWARE_FAILURE;
}

extern "C" psa_status_t psa_se05x_rsa_verify(psa_key_handle_t key_handle,
                                             psa_algorithm_t alg,
                                             const uint8_t *hash, size_t hash_length,
                                             const uint8_t *signature, size_t signature_length) {
    int ret = 0;
    switch (alg) {
        case PSA_ALG_RSA_PKCS1V15_SIGN_RAW:
        case PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256):
            ret = SE05X.VerifyRSASSA_PKCS1(psa_to_se_id(key_handle), hash, hash_length, signature, signature_length);
            break;
        case PSA_ALG_RSA_PSS(PSA_ALG_SHA_256):
            ret = SE05X.VerifyRSASSA_PSS(psa_to_se_id(key_handle), (uint8_t*)hash, hash_length, signature, signature_length);
            break;
        default: return PSA_ERROR_NOT_SUPPORTED;
    }
    return ret == 1 ? PSA_SUCCESS : PSA_ERROR_INVALID_SIGNATURE;
}

// ---------------- Key management ----------------
extern "C" psa_status_t psa_se05x_import_key(const psa_key_attributes_t *attributes,
                                             const uint8_t *data, size_t data_length,
                                             psa_key_handle_t *key_handle) {
    int se_id = *key_handle;
    if (psa_get_key_type(attributes) == PSA_KEY_TYPE_AES) {
        if (SE05X.writeAESKey(se_id, data, data_length) != 1)
            return PSA_ERROR_HARDWARE_FAILURE;
    } else if (PSA_KEY_TYPE_IS_ECC(psa_get_key_type(attributes))) {
        if (SE05X.importPublicKey(se_id, data, data_length) != 1)
            return PSA_ERROR_HARDWARE_FAILURE;
    } else if (PSA_KEY_TYPE_IS_RSA(psa_get_key_type(attributes))) {
        // Expect DER-encoded key: modulus + exponent
        // int SE05XClass::writeRSAKey(int keyID, SE05x_RSABitLength_t keyBitLength, 2
        //     const uint8_t *p, size_t pLen, const uint8_t *q, size_t qLen, const uint8_t *dp, size_t dpLen, const uint8_t *dq, size_t dqLen, 8
        //     const uint8_t *qInv, size_t qInvLen, const uint8_t *pubExp, size_t pubExpLen, const uint8_t *priv, size_t privLen, const uint8_t *pubMod, size_t pubModLen, 
        //     SE05x_RSAKeyFormat_t rsa_format, bool transient, SE05x_KeyPart_t keyType, pSe05xPolicy_t policy)
        if (SE05X.writeRSAKey(se_id, SE05x_RSABitLength_t::kSE05x_RSABitLength_2048,
                              nullptr, 0, nullptr, 0, nullptr, 0, nullptr, 0,
                              nullptr, 0, nullptr, 0, data, data_length, nullptr, 0,
                              SE05x_RSAKeyFormat_t::kSE05x_RSAKeyFormat_RAW, false, kSE05x_KeyPart_Public, nullptr) != 1)
            return PSA_ERROR_HARDWARE_FAILURE;
    } else return PSA_ERROR_NOT_SUPPORTED;
    return PSA_SUCCESS;
}

extern "C" psa_status_t psa_se05x_generate_key(const psa_key_attributes_t *attributes,
                                               psa_key_handle_t *key_handle) {
    int se_id = *key_handle;
    if (psa_get_key_type(attributes) == PSA_KEY_TYPE_AES) {
        // For AES just write random key
        uint8_t key[32]; // max AES-256
        if (psa_se05x_generate_random(key, psa_get_key_bits(attributes) / 8) != PSA_SUCCESS)
            return PSA_ERROR_HARDWARE_FAILURE;
        return psa_se05x_import_key(attributes, key, psa_get_key_bits(attributes) / 8, key_handle);
    } else if (PSA_KEY_TYPE_IS_ECC(psa_get_key_type(attributes))) {
        int curve = kSE05x_ECCurve_NIST_P256;
        if (psa_get_key_type(attributes) == PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1)) {
            if (SE05X.generatePrivateKey(se_id, nullptr) != 1)
                return PSA_ERROR_HARDWARE_FAILURE;
        }
    } else if (PSA_KEY_TYPE_IS_RSA(psa_get_key_type(attributes))) {
        size_t keyLen = 0;
        if (SE05X.generatePrivateRSAKey(se_id, nullptr, nullptr, nullptr, nullptr, psa_get_key_bits(attributes)) != 1)
            return PSA_ERROR_HARDWARE_FAILURE;
    } else return PSA_ERROR_NOT_SUPPORTED;
    return PSA_SUCCESS;
}
    
extern "C" psa_status_t psa_se05x_destroy_key(psa_key_handle_t key_handle) {
    if (SE05X.deleteBinaryObject(psa_to_se_id(key_handle)) != 1)
        return PSA_ERROR_HARDWARE_FAILURE;
    return PSA_SUCCESS;
}