#include <Arduino.h>
#include "WiFiC3.h"
#include "WiFiClient.h"
#include "IPAddress.h"
#include "arduino_secrets.h"
#include "mbedtls_config.h"
#include "psa_se05x_wrapper.h"
#include "mbedtls_psa_glue.h"
#include "SE05X.h"

#include "psa/crypto.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/error.h"
#include "utils.h"

// Hardware random number generation test

void test_random_generation()
{
    Serial.println("\n--- Random Number Generation Test ---");
    
    uint8_t random_bytes[32];
    psa_status_t status = psa_generate_random(random_bytes, sizeof(random_bytes));
    
    if (status == PSA_SUCCESS)
    {
        Serial.println("Generated 32 random bytes from SE05X:");
        Serial.print("Random data: ");
        for (int i = 0; i < 16; i++) {
            if (random_bytes[i] < 0x10) Serial.print("0");
            Serial.print(random_bytes[i], HEX);
        }
        Serial.println("...");
    }
    else
    {
        Serial.print("ERROR: Random generation failed: 0x");
        Serial.println(status, HEX);
    }
}

// ECDSA signing and verification test

void test_ecdsa_operations(psa_key_id_t *key_id)
{
    Serial.println("\n--- ECDSA Sign/Verify Test ---");
    
    uint8_t data[] = "Test message for ECDSA signing";
    uint8_t hash[32];
    size_t hash_len = 0;
    
    Serial.println("Computing SHA-256 hash...");
    psa_status_t status = psa_hash_compute(
        PSA_ALG_SHA_256,
        data, sizeof(data) - 1,
        hash, sizeof(hash),
        &hash_len
    );
    
    if (status != PSA_SUCCESS)
    {
        Serial.print("ERROR: Hash computation failed: 0x");
        Serial.println(status, HEX);
        return;
    }
    
    Serial.print("Hash computed: ");
    Serial.print(hash_len);
    Serial.println(" bytes");
    
    uint8_t signature[80];
    size_t sig_len;
    
    Serial.println("Signing with SE05X...");
    status = psa_sign_hash(
        *key_id,
        PSA_ALG_ECDSA(PSA_ALG_SHA_256),
        hash, hash_len,
        signature, sizeof(signature),
        &sig_len
    );
    
    if (status == PSA_SUCCESS)
    {
        Serial.print("Signature generated: ");
        Serial.print(sig_len);
        Serial.println(" bytes (DER format)");
        
        Serial.println("Verifying signature...");
        status = psa_verify_hash(
            *key_id,
            PSA_ALG_ECDSA(PSA_ALG_SHA_256),
            hash, hash_len,
            signature, sig_len
        );
        
        if (status == PSA_SUCCESS)
        {
            Serial.println("Signature verified successfully");
        }
        else
        {
            Serial.print("ERROR: Signature verification failed: 0x");
            Serial.println(status, HEX);
        }
    }
    else
    {
        Serial.print("ERROR: Signing failed: 0x");
        Serial.println(status, HEX);
    }
}
// AES encryption and decryption test

void test_aes_operations()
{
    Serial.println("\n--- AES-128 ECB Test ---");
    
    const psa_key_id_t aes_key_id = 100;
    
    // Delete any existing key
    SE05X.deleteBinaryObject(aes_key_id);
    delay(50);
    
    // Generate and import AES key using PSA
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 128);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_ECB_NO_PADDING);
    psa_set_key_id(&attr, aes_key_id);
    psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
    
    psa_key_handle_t key_handle = aes_key_id;
    psa_status_t status = psa_generate_key(&attr, &key_handle);
    
    if (status != PSA_SUCCESS)
    {
        Serial.print("ERROR: AES key generation failed: 0x");
        Serial.println(status, HEX);
        Serial.println("AES test: FAIL");
        return;
    }
    
    Serial.println("AES-128 key generated");
    
    uint8_t plaintext[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
    };
    uint8_t ciphertext[16];
    uint8_t decrypted[16];
    size_t cipher_len = 0;
    size_t decrypt_len = 0;
    
    Serial.print("Plaintext: ");
    for (int i = 0; i < 16; i++) {
        Serial.print((char)plaintext[i]);
    }
    Serial.println();
    
    status = psa_se05x_aes_encrypt(
        aes_key_id,
        PSA_ALG_ECB_NO_PADDING,
        plaintext, sizeof(plaintext),
        ciphertext, sizeof(ciphertext),
        &cipher_len
    );
    
    if (status == PSA_SUCCESS)
    {
        Serial.print("Encrypted ");
        Serial.print(cipher_len);
        Serial.println(" bytes");
        
        status = psa_se05x_aes_decrypt(
            aes_key_id,
            PSA_ALG_ECB_NO_PADDING,
            ciphertext, cipher_len,
            decrypted, sizeof(decrypted),
            &decrypt_len
        );
        
        if (status == PSA_SUCCESS && memcmp(plaintext, decrypted, 16) == 0)
        {
            Serial.println("Decryption verified");
            Serial.println("AES test: PASS");
        }
        else
        {
            Serial.println("ERROR: Decryption failed or mismatch");
            Serial.println("AES test: FAIL");
        }
    }
    else
    {
        Serial.print("ERROR: Encryption failed: 0x");
        Serial.println(status, HEX);
        Serial.println("AES test: FAIL");
    }
    
    psa_destroy_key(aes_key_id);
}

// RSA key generation and signing test

void test_rsa_operations()
{
    Serial.println("\n--- RSA-2048 Test ---");
    
    const psa_key_id_t rsa_key_id = 100;
    
    SE05X.deleteBinaryObject(rsa_key_id);
    delay(50);
    
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attr, 2048);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attr, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256));
    psa_set_key_id(&attr, rsa_key_id);
    psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_PERSISTENT);
    
    Serial.println("Generating RSA-2048 keypair (this may take seconds)...");
    
    unsigned long start_time = millis();
    psa_key_handle_t key_handle = rsa_key_id;
    psa_status_t status = psa_generate_key(&attr, &key_handle);
    unsigned long generation_time = millis() - start_time;
    
    if (status != PSA_SUCCESS)
    {
        Serial.print("ERROR: RSA key generation failed: 0x");
        Serial.println(status, HEX);
        Serial.println("RSA test: FAIL");
        return;
    }
    
    Serial.print("RSA keypair generated in ");
    Serial.print(generation_time);
    Serial.println(" ms");
    
    // Test signing
    uint8_t hash[32];
    psa_generate_random(hash, sizeof(hash));
    
    uint8_t signature[256];
    size_t sig_len;
    
    status = psa_sign_hash(
        rsa_key_id,
        PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256),
        hash, sizeof(hash),
        signature, sizeof(signature),
        &sig_len
    );
    
    if (status == PSA_SUCCESS)
    {
        Serial.print("RSA signature generated: ");
        Serial.print(sig_len);
        Serial.println(" bytes");
        Serial.println("RSA test: PASS");
    }
    else
    {
        Serial.print("ERROR: RSA signing failed: 0x");
        Serial.println(status, HEX);
        Serial.println("RSA test: FAIL");
    }
    
    psa_destroy_key(rsa_key_id);
}

void test_ecdhe_operations()
{
    Serial.println("\n--- ECDHE Key Agreement Test ---");

    const psa_key_id_t key_id_A = 300;
    const psa_key_id_t key_id_B = 301;

    SE05X.deleteBinaryObject(key_id_A);
    SE05X.deleteBinaryObject(key_id_B);
    delay(50);

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
    psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);

    // --- Generate keypair A ---
    psa_set_key_id(&attr, key_id_A);
    psa_key_handle_t handle_A = key_id_A;
    psa_status_t status = psa_generate_key(&attr, &handle_A);

    if (status != PSA_SUCCESS) {
        Serial.println("ERROR: Key A generation failed");
        return;
    }

    // --- Generate keypair B ---
    psa_set_key_id(&attr, key_id_B);
    psa_key_handle_t handle_B = key_id_B;
    status = psa_generate_key(&attr, &handle_B);

    if (status != PSA_SUCCESS) {
        Serial.println("ERROR: Key B generation failed");
        return;
    }

    Serial.println("Keypairs generated");

    // --- Export public keys ---
    uint8_t pub_A[100], pub_B[100];
    size_t pub_A_len = 0, pub_B_len = 0;

    status = psa_export_public_key(handle_A, pub_A, sizeof(pub_A), &pub_A_len);
    if (status != PSA_SUCCESS) {
        Serial.println("ERROR: export pub_A failed");
        return;
    }

    status = psa_export_public_key(handle_B, pub_B, sizeof(pub_B), &pub_B_len);
    if (status != PSA_SUCCESS) {
        Serial.println("ERROR: export pub_B failed");
        return;
    }

    Serial.print("pub_A_len: "); Serial.println(pub_A_len);
    Serial.print("pub_B_len: "); Serial.println(pub_B_len);

    // --- Derive shared secrets ---
    uint8_t secret_A[32], secret_B[32];
    size_t len_A = 0, len_B = 0;

    status = psa_raw_key_agreement(
        PSA_ALG_ECDH,
        handle_A,
        pub_B, pub_B_len,
        secret_A, sizeof(secret_A),
        &len_A
    );

    if (status != PSA_SUCCESS) {
        Serial.print("ERROR: ECDH A failed: 0x");
        Serial.println(status, HEX);
        return;
    }

    status = psa_raw_key_agreement(
        PSA_ALG_ECDH,
        handle_B,
        pub_A, pub_A_len,
        secret_B, sizeof(secret_B),
        &len_B
    );

    if (status != PSA_SUCCESS) {
        Serial.print("ERROR: ECDH B failed: 0x");
        Serial.println(status, HEX);
        return;
    }

    Serial.print("Secret A len: "); Serial.println(len_A);
    Serial.print("Secret B len: "); Serial.println(len_B);

    // --- Debug dump (first bytes only) ---
    Serial.print("Secret A: ");
    for (int i = 0; i < 8; i++) {
        if (secret_A[i] < 0x10) Serial.print("0");
        Serial.print(secret_A[i], HEX);
    }
    Serial.println("...");

    Serial.print("Secret B: ");
    for (int i = 0; i < 8; i++) {
        if (secret_B[i] < 0x10) Serial.print("0");
        Serial.print(secret_B[i], HEX);
    }
    Serial.println("...");

    // --- Compare ---
    if (len_A == len_B && memcmp(secret_A, secret_B, len_A) == 0) {
        Serial.println("ECDHE test: PASS");
    } else {
        Serial.println("ECDHE test: FAIL (mismatch)");
    }

    psa_destroy_key(key_id_A);
    psa_destroy_key(key_id_B);
}

