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


// TLS configuration

void setup_tls(WiFiClient *tcpClient, mbedtls_ssl_context *ssl, mbedtls_ssl_config *conf, mbedtls_x509_crt *cacert,
    int (*wifi_send)(void *ctx, const unsigned char *buf, size_t len), 
    int (*wifi_recv)(void *ctx, unsigned char *buf, size_t len)
)
{
    Serial.println("Setting up TLS connection...");
    
    mbedtls_ssl_init(ssl);
    mbedtls_ssl_config_init(conf);
    mbedtls_x509_crt_init(cacert);

    int ret = mbedtls_ssl_config_defaults(
        conf,
        MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT);

    if (ret != 0)
    {
        Serial.print("ERROR: SSL config defaults failed: 0x");
        Serial.println(-ret, HEX);
        while (1);
    }

    mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_NONE);
    
    Serial.println("Configuring hardware-backed RNG...");
    mbedtls_ssl_conf_rng(conf, mbedtls_psa_get_random, NULL);

    ret = mbedtls_ssl_setup(ssl, conf);
    if (ret != 0)
    {
        Serial.print("ERROR: SSL setup failed: 0x");
        Serial.println(-ret, HEX);
        while (1);
    }

    mbedtls_ssl_set_hostname(ssl, "www.google.com");
    mbedtls_ssl_set_bio(ssl, tcpClient, wifi_send, wifi_recv, NULL);
                        
    Serial.println("TLS setup complete");
}

// TLS handshake

void perform_tls_handshake(WiFiClient *tcpClient, mbedtls_ssl_context *ssl)
{
    Serial.println("Starting TLS handshake...");

    int ret;
    int retry_count = 0;
    int last_error = 0;
    
    while ((ret = mbedtls_ssl_handshake(ssl)) != 0)
    {
        // Print status every 50 iterations
        if (retry_count % 50 == 0) {
            Serial.print("Handshake status: 0x");
            Serial.print(-ret, HEX);
            
            if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
                Serial.print(" (WANT_READ - waiting for data)");
            } else if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                Serial.print(" (WANT_WRITE - waiting to send)");
            }
            
            // Check TCP connection status
            Serial.print(" - TCP connected: ");
            Serial.print(tcpClient->connected() ? "Yes" : "No");
            Serial.print(", available: ");
            Serial.println(tcpClient->available());
        }
        
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            char errbuf[128];
            mbedtls_strerror(ret, errbuf, sizeof(errbuf));
            Serial.print("ERROR: Handshake failed: 0x");
            Serial.print(-ret, HEX);
            Serial.print(" - ");
            Serial.println(errbuf);
            while (1);
        }
        
        retry_count++;
        
        if (retry_count > 500) {
            Serial.println("\nERROR: Handshake timeout after 500 iterations");
            Serial.println("Last error was: 0x");
            Serial.print(-ret, HEX);
            Serial.println("\nTCP connection status:");
            Serial.print("  Connected: ");
            Serial.println(tcpClient->connected());
            Serial.print("  Available bytes: ");
            Serial.println(tcpClient->available());
            while (1);
        }
        
        delay(10);
    }

    Serial.println("\nTLS handshake complete");
    
    const char* cipher = mbedtls_ssl_get_ciphersuite(ssl);
    Serial.print("Cipher suite: ");
    Serial.println(cipher);
}

// HTTPS request

void https_request(mbedtls_ssl_context *ssl)
{
    const char *req =
        "GET / HTTP/1.1\r\n"
        "Host: www.google.com\r\n"
        "Connection: close\r\n\r\n";

    Serial.println("Sending HTTPS request...");
    mbedtls_ssl_write(ssl, (const unsigned char *)req, strlen(req));

    unsigned char buf[512];
    int len;

    Serial.println("Reading response...");
    while ((len = mbedtls_ssl_read(ssl, buf, sizeof(buf) - 1)) > 0)
    {
        buf[len] = 0;
        Serial.print((char *)buf);
    }
    
    Serial.println("\n\nHTTPS request complete");
}

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
    
    const psa_key_id_t rsa_key_id = 200;
    
    SE05X.deleteBinaryObject(rsa_key_id);
    delay(50);
    
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attr, 2048);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attr, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256));
    psa_set_key_id(&attr, rsa_key_id);
    psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
    
    Serial.println("Generating RSA-2048 keypair (this may take 10-30 seconds)...");
    
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
