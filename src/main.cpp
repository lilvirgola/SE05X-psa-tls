#include <Arduino.h>
#include "psa_se05x_wrapper.h"

#define AES_KEY_ID 666
#define PLAINTEXT "Hello SE05X PSA!"
#define PLAINTEXT_LEN (sizeof(PLAINTEXT)-1)

uint8_t ciphertext[64];
size_t ciphertext_len = sizeof(ciphertext);

uint8_t decrypted[64];
size_t decrypted_len = sizeof(decrypted);

uint8_t hash[32];
size_t hash_len = sizeof(hash);

void printHex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (buf[i] < 0x10) Serial.print("0");
        Serial.print(buf[i], HEX);
        Serial.print(" ");
    }
    Serial.println();
}

void setup() {
    Serial.begin(115200);
    while(!Serial);

    Serial.println("PSA SE05X Test");

    if (psa_se05x_init() != PSA_SUCCESS) {
        Serial.println("Failed to init SE05X wrapper");
        return;
    }

    // Generate random AES key
    uint8_t key[16];
    if (psa_se05x_generate_random(key, sizeof(key)) != PSA_SUCCESS) {
        Serial.println("Failed to generate random key");
        return;
    }
    Serial.print("Random key: ");
    printHex(key, sizeof(key));

    // Import AES key
    psa_key_handle_t key_handle = AES_KEY_ID;
    psa_key_attributes_t attr;
    // assert the key ID is free
    psa_status_t remove_status = psa_se05x_destroy_key(key_handle);
    if (remove_status != PSA_SUCCESS) {
        Serial.print("no key to remove: ");
        Serial.println(remove_status);
    } else {
        Serial.println("Key removed successfully");
    }
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 128);
    psa_status_t status = psa_se05x_import_key(&attr, key, sizeof(key), &key_handle);
    if (status != PSA_SUCCESS) {
        Serial.println("Failed to import AES key");
        Serial.print("Error code: ");
        Serial.println(status);
        return;
    }
    Serial.println("AES key imported");

    // Hash plaintext
    if (psa_se05x_hash_compute(PSA_ALG_SHA_256, (const uint8_t*)PLAINTEXT, PLAINTEXT_LEN,
                               hash, sizeof(hash), &hash_len) != PSA_SUCCESS) {
        Serial.println("SHA-256 failed");
        return;
    }
    Serial.print("SHA-256: ");
    printHex(hash, hash_len);

    // AES ECB encrypt
    if (psa_se05x_aes_encrypt(key_handle, 0, (const uint8_t*)PLAINTEXT, PLAINTEXT_LEN,
                              ciphertext, sizeof(ciphertext), &ciphertext_len) != PSA_SUCCESS) {
        Serial.println("AES encrypt failed");
        return;
    }
    Serial.print("Ciphertext: ");
    printHex(ciphertext, ciphertext_len);

    // AES ECB decrypt
    if (psa_se05x_aes_decrypt(key_handle, 0, ciphertext, ciphertext_len,
                              decrypted, sizeof(decrypted), &decrypted_len) != PSA_SUCCESS) {
        Serial.println("AES decrypt failed");
        return;
    }
    Serial.print("Decrypted: ");
    Serial.write(decrypted, decrypted_len);
    Serial.println();

    // remove AES key
    remove_status = psa_se05x_destroy_key(key_handle);
    if (remove_status != PSA_SUCCESS) {
        Serial.print("Failed to remove key: ");
        Serial.println(remove_status);
    } else {
        Serial.println("Key removed successfully");
    }
}

void loop() {
    // nothing
}