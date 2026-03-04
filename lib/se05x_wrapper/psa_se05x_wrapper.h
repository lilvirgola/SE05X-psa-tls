#ifndef PSA_SE05X_WRAPPER_H
#define PSA_SE05X_WRAPPER_H

#include <stddef.h>
#include <stdint.h>
#include "psa/crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

// Initialization
psa_status_t psa_se05x_init(void);

// Random number generation
psa_status_t psa_se05x_generate_random(
    uint8_t *output,
    size_t output_size);

// Hash computation
psa_status_t psa_se05x_hash_compute(
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *hash,
    size_t hash_size,
    size_t *hash_length);

// AES encryption and decryption
psa_status_t psa_se05x_aes_encrypt(
    psa_key_handle_t key_handle,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length);

psa_status_t psa_se05x_aes_decrypt(
    psa_key_handle_t key_handle,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length);

// ECDSA signing and verification
psa_status_t psa_se05x_ecdsa_sign(
    psa_key_handle_t key_handle,
    psa_algorithm_t alg,
    const uint8_t *hash,
    size_t hash_length,
    uint8_t *signature,
    size_t signature_size,
    size_t *signature_length);

psa_status_t psa_se05x_ecdsa_verify(
    psa_key_handle_t key_handle,
    psa_algorithm_t alg,
    const uint8_t *hash,
    size_t hash_length,
    const uint8_t *signature,
    size_t signature_length);

// RSA signing and verification
psa_status_t psa_se05x_rsa_sign(
    psa_key_handle_t key_handle,
    psa_algorithm_t alg,
    const uint8_t *hash,
    size_t hash_length,
    uint8_t *signature,
    size_t signature_size,
    size_t *signature_length);

psa_status_t psa_se05x_rsa_verify(
    psa_key_handle_t key_handle,
    psa_algorithm_t alg,
    const uint8_t *hash,
    size_t hash_length,
    const uint8_t *signature,
    size_t signature_length);

// RSA encryption and decryption
psa_status_t psa_se05x_rsa_encrypt(
    psa_key_handle_t key_handle,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length);

psa_status_t psa_se05x_rsa_decrypt(
    psa_key_handle_t key_handle,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length);

// Key management operations
psa_status_t psa_se05x_import_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data,
    size_t data_length,
    psa_key_handle_t *key_handle);

psa_status_t psa_se05x_generate_key(
    const psa_key_attributes_t *attributes,
    psa_key_handle_t *key_handle);

psa_status_t psa_se05x_destroy_key(
    psa_key_handle_t key_handle);

// Standard PSA Crypto API implementations
psa_status_t psa_crypto_init(void);

psa_status_t psa_generate_key(
    const psa_key_attributes_t *attr,
    psa_key_handle_t *key_handle);

psa_status_t psa_destroy_key(
    psa_key_handle_t key_handle);

psa_status_t psa_import_key(
    const psa_key_attributes_t *attr,
    const uint8_t *data,
    size_t data_len,
    psa_key_handle_t *key_handle);

psa_status_t psa_generate_random(
    uint8_t *output,
    size_t output_size);

psa_status_t psa_hash_compute(
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *hash,
    size_t hash_size,
    size_t *hash_length);

psa_status_t psa_sign_hash(
    psa_key_id_t key,
    psa_algorithm_t alg,
    const uint8_t *hash,
    size_t hash_length,
    uint8_t *signature,
    size_t signature_size,
    size_t *signature_length);

psa_status_t psa_verify_hash(
    psa_key_id_t key,
    psa_algorithm_t alg,
    const uint8_t *hash,
    size_t hash_length,
    const uint8_t *signature,
    size_t signature_length);

psa_status_t psa_export_public_key(
    psa_key_id_t key,
    uint8_t *data,
    size_t data_size,
    size_t *data_length);

#ifdef __cplusplus
}
#endif

#endif // PSA_SE05X_WRAPPER_H