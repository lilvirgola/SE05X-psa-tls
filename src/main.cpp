#include <Arduino.h>
#include "SE05X.h"

void testECC();
void testRSA();
void testAES();

void setup() {
    Serial.begin(115200);
    while (!Serial);

    if (SE05X.begin() != 1) {
        Serial.println("SE05X init failed");
        while(1);
    }
    Serial.println("SE05X initialized");
}


void loop() {
    testECC();
    testRSA();
    testAES();
    delay(5000);
}

void testECC() {
    byte pubKey[64];
    size_t pubLen;

    int keyID = 0x1234;

    if (SE05X.generatePrivateKey(keyID, pubKey, sizeof(pubKey), &pubLen)) {
        Serial.println("ECC keypair generated");
        Serial.print("Public key: ");
        for (size_t i = 0; i < pubLen; i++) {
            Serial.print(pubKey[i], HEX); Serial.print(" ");
        }
        Serial.println();
    } else {
        Serial.println("ECC keypair generation failed");
    }
}

void testRSA() {
    byte modulus[256];
    byte exponent[3];
    size_t modLen = sizeof(modulus);
    size_t expLen = sizeof(exponent);

    int keyID = 0x5678;

    if (SE05X.generatePrivateRSAKey(keyID, modulus, &modLen, exponent, &expLen, 2048)) {
        Serial.println("RSA keypair generated");
    } else {
        Serial.println("RSA keypair generation failed");
    }
}

void testAES() {
    byte key[16] = {0x00,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    int keyID = 0x1001;
    SE05X.writeAESKey(keyID, key, sizeof(key));

    const byte plaintext[16] = {
        'H','e','l','l','o',' ','S','E','0','5','0',' ','E','C','B','!'
    };
    byte ciphertext[16];
    size_t ctLen;

    if (SE05X.AES_ECB_encrypt(keyID, plaintext, sizeof(plaintext), ciphertext, &ctLen)) {
        Serial.println("AES ECB encrypt success");
    } else {
        Serial.println("AES ECB encrypt failed");
    }
}
