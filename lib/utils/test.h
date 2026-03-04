#ifndef TEST_H
#define TEST_H
#include "WiFiClient.h"
#include "psa/crypto.h"

void setup_tls(WiFiClient *tcpClient, mbedtls_ssl_context *ssl, mbedtls_ssl_config *conf, mbedtls_x509_crt *cacert,
    int (*wifi_send)(void *ctx, const unsigned char *buf, size_t len), 
    int (*wifi_recv)(void *ctx, unsigned char *buf, size_t len)
);

void perform_tls_handshake(WiFiClient *tcpClient, mbedtls_ssl_context *ssl);

void https_request(mbedtls_ssl_context *ssl);

void test_random_generation();

void test_ecdsa_operations(psa_key_id_t *key_id);

void test_aes_operations();

void test_rsa_operations();
#endif // TEST_H