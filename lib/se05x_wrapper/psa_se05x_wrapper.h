#ifndef PSA_SE05X_WRAPPER_H
#define PSA_SE05X_WRAPPER_H

#include <stddef.h>
#include <stdint.h>
#include "psa/crypto.h"  // PSA status & key types

#ifdef __cplusplus
extern "C" {
#endif

// Initialize SE05X wrapper
psa_status_t psa_se05x_init(void);

// Random
psa_status_t psa_se05x_generate_random(uint8_t *output, size_t output_size);

// One-shot hash
psa_status_t psa_se05x_hash_compute(psa_algorithm_t alg,
                                    const uint8_t *input, size_t input_length,
                                    uint8_t *hash, size_t hash_size, size_t *hash_length);

// AES encrypt/decrypt ECB
psa_status_t psa_se05x_aes_encrypt(psa_key_handle_t key_handle,
                                   psa_algorithm_t alg,
                                   const uint8_t *input, size_t input_length,
                                   uint8_t *output, size_t output_size,
                                   size_t *output_length);

psa_status_t psa_se05x_aes_decrypt(psa_key_handle_t key_handle,
                                   psa_algorithm_t alg,
                                   const uint8_t *input, size_t input_length,
                                   uint8_t *output, size_t output_size,
                                   size_t *output_length);

// ECC sign/verify
psa_status_t psa_se05x_ecdsa_sign(psa_key_handle_t key_handle,
                                  psa_algorithm_t alg,
                                  const uint8_t *hash, size_t hash_length,
                                  uint8_t *signature, size_t signature_size,
                                  size_t *signature_length);

psa_status_t psa_se05x_ecdsa_verify(psa_key_handle_t key_handle,
                                    psa_algorithm_t alg,
                                    const uint8_t *hash, size_t hash_length,
                                    const uint8_t *signature, size_t signature_length);

// RSA sign/verify (PKCS1 v1.5 / PSS) & encrypt/decrypt
psa_status_t psa_se05x_rsa_sign(psa_key_handle_t key_handle,
                                psa_algorithm_t alg,
                                const uint8_t *hash, size_t hash_length,
                                uint8_t *signature, size_t signature_size,
                                size_t *signature_length);

psa_status_t psa_se05x_rsa_verify(psa_key_handle_t key_handle,
                                  psa_algorithm_t alg,
                                  const uint8_t *hash, size_t hash_length,
                                  const uint8_t *signature, size_t signature_length);

psa_status_t psa_se05x_rsa_encrypt(psa_key_handle_t key_handle,
                                   psa_algorithm_t alg,
                                   const uint8_t *input, size_t input_length,
                                   uint8_t *output, size_t output_size,
                                   size_t *output_length);

psa_status_t psa_se05x_rsa_decrypt(psa_key_handle_t key_handle,
                                   psa_algorithm_t alg,
                                   const uint8_t *input, size_t input_length,
                                   uint8_t *output, size_t output_size,
                                   size_t *output_length);

// Key management
psa_status_t psa_se05x_import_key(const psa_key_attributes_t *attributes,
                                  const uint8_t *data, size_t data_length,
                                  psa_key_handle_t *key_handle);

psa_status_t psa_se05x_generate_key(const psa_key_attributes_t *attributes,
                                    psa_key_handle_t *key_handle);

psa_status_t psa_se05x_destroy_key(psa_key_handle_t key_handle);

#ifdef __cplusplus
}
#endif

#endif // PSA_SE05X_WRAPPER_H