#include <Arduino.h>
#include "WiFiC3.h"
#include "WiFiClient.h"
#include "IPAddress.h"
#include "arduino_secrets.h"
#include "mbedtls_config.h"
#include "psa_se05x_wrapper.h"
#include "mbedtls_psa_glue.h"
#include "SE05X.h"
#include <PubSubClient.h>

#include "psa/crypto.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"

// WiFi to mbedTLS glue layer

int wifi_send(void *ctx, const unsigned char *buf, size_t len)
{
    WiFiClient *c = (WiFiClient *)ctx;
    int ret = c->write(buf, len);
    if (ret <= 0)
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    return ret;
}

int wifi_recv(void *ctx, unsigned char *buf, size_t len)
{
    WiFiClient *c = (WiFiClient *)ctx;

    if (!c->connected())
        return MBEDTLS_ERR_NET_CONN_RESET;

    if (!c->available())
        return MBEDTLS_ERR_SSL_WANT_READ;

    int ret = c->read(buf, len);
    if (ret < 0)
        return MBEDTLS_ERR_SSL_WANT_READ;

    return ret;
}

// WiFi connection

void connect_wifi(const char *ssid, const char *pass)
{
    // scan for networks
    Serial.println("Scanning for WiFi networks...");
    int num_networks = WiFi.scanNetworks();
    if (num_networks == 0) {
        Serial.println("No WiFi networks found");
    } else {
        Serial.print(num_networks);        Serial.println(" WiFi networks found:");
        for (int i = 0; i < num_networks; i++) {
            Serial.print("  ");Serial.print(i + 1);
            Serial.print(": ");Serial.print(WiFi.SSID(i));
            Serial.print(" (");Serial.print(WiFi.RSSI(i));Serial.print(" dBm)");
            Serial.print(" Encryption: ");Serial.println(WiFi.encryptionType(i));
        }
    }
    Serial.println("Connecting to WiFi...");
    int code = WiFi.begin(ssid, pass);
    while (code != WL_CONNECTED)
    {
        Serial.print("Connection failed with code ");        
        Serial.println(code);
        delay(3000);
        Serial.println("Retrying WiFi connection...");
        code = WiFi.begin(ssid, pass);
    }

    Serial.println("WiFi connected");
    Serial.print("IP address: ");
    Serial.println(WiFi.localIP());
}

// PSA and SE05X key setup

void setup_psa_key(psa_key_id_t *key_id)
{
    Serial.println("Initializing PSA Crypto with SE05X...");
    
    if (psa_crypto_init() != PSA_SUCCESS)
    {
        Serial.println("ERROR: PSA initialization failed");
        while (1);
    }

    *key_id = 1;
    
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_id(&attr, *key_id);


    Serial.print("[setup_psa_key] attr type=0x"); Serial.println(psa_get_key_type(&attr), HEX);
    Serial.print("[setup_psa_key] attr bits="); Serial.println(psa_get_key_bits(&attr));
    Serial.print("[setup_psa_key] attr usage=0x"); Serial.println(psa_get_key_usage_flags(&attr), HEX);
    Serial.print("[setup_psa_key] attr alg=0x"); Serial.println(psa_get_key_algorithm(&attr), HEX);
    Serial.print("[setup_psa_key] attr id="); Serial.println(psa_get_key_id(&attr));
    Serial.print("[setup_psa_key] attr lifetime=0x"); Serial.println(psa_get_key_lifetime(&attr), HEX);


    psa_status_t status = psa_generate_key(&attr, key_id);
    
    if (status == PSA_ERROR_ALREADY_EXISTS)
    {
        Serial.println("Using existing SE05X key");
    }
    else if (status == PSA_SUCCESS)
    {
        Serial.println("Generated new SE05X key");
    }
    else
    {
        Serial.print("ERROR: Key generation failed with status 0x");
        Serial.println(status, HEX);
        while (1);
    }

    Serial.print("SE05X key ID: ");
    Serial.println(*key_id);
    Serial.println("Private key secured in SE05X hardware");
    
    delay(100);
    
    uint8_t pubkey[128];
    size_t pubkey_len;
    status = psa_export_public_key(*key_id, pubkey, sizeof(pubkey), &pubkey_len);
    
    if (status == PSA_SUCCESS)
    {
        Serial.print("Public key exported: ");
        Serial.print(pubkey_len);
        Serial.println(" bytes");
    }
    else
    {
        Serial.print("WARNING: Public key export failed with status 0x");
        Serial.println(status, HEX);
        Serial.println("Key is still usable for signing operations");
    }
}

typedef struct {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
} tls_context_t;


// Generic TLS connect (SE05X-backed via PSA)
bool tls_connect(
    tls_context_t *tls,
    WiFiClient *tcpClient,
    const char *hostname,
    int port,
    const unsigned char *ca_cert,
    size_t ca_cert_len)
{
    Serial.println("\n=== TLS CONNECT (SE05X) ===");

    // --- PSA INIT ---
    if (psa_crypto_init() != PSA_SUCCESS) {
        Serial.println("ERROR: PSA init failed");
        return false;
    }

    // --- TCP ---
    Serial.print("Connecting to ");
    Serial.print(hostname);
    Serial.print(":");
    Serial.println(port);

    if (!tcpClient->connect(hostname, port)) {
        Serial.println("ERROR: TCP connect failed");
        return false;
    }

    Serial.println("TCP connected");

    // --- INIT ---
    mbedtls_ssl_init(&tls->ssl);
    mbedtls_ssl_config_init(&tls->conf);
    mbedtls_x509_crt_init(&tls->cacert);

    // --- LOAD CA ---
    int ret = mbedtls_x509_crt_parse(
        &tls->cacert,
        ca_cert,
        ca_cert_len);

    if (ret != 0) {
        Serial.print("ERROR: CA parse failed: 0x");
        Serial.println(-ret, HEX);
        return false;
    }

    // --- CONFIG ---
    ret = mbedtls_ssl_config_defaults(
        &tls->conf,
        MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT);

    if (ret != 0) {
        Serial.print("ERROR: SSL config failed: 0x");
        Serial.println(-ret, HEX);
        return false;
    }

    // NOTE: this needs to be fixed to support proper certificate verification.
    mbedtls_ssl_conf_authmode(&tls->conf, MBEDTLS_SSL_VERIFY_NONE);

    // --- SE05X RNG ---
    mbedtls_ssl_conf_rng(&tls->conf, mbedtls_psa_get_random, NULL);

    // --- SETUP ---
    ret = mbedtls_ssl_setup(&tls->ssl, &tls->conf);
    if (ret != 0) {
        Serial.print("ERROR: SSL setup failed: 0x");
        Serial.println(-ret, HEX);
        return false;
    }

    mbedtls_ssl_set_hostname(&tls->ssl, hostname);
    mbedtls_ssl_set_bio(&tls->ssl, tcpClient, wifi_send, wifi_recv, NULL);

    // --- HANDSHAKE ---
    Serial.println("Starting TLS handshake...");

    int retry = 0;
    while ((ret = mbedtls_ssl_handshake(&tls->ssl)) != 0) {

        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE) {

            Serial.print("ERROR: Handshake failed: 0x");
            Serial.println(-ret, HEX);
            return false;
        }

        if (++retry > 500) {
            Serial.println("ERROR: Handshake timeout");
            return false;
        }

        delay(10);
    }

    Serial.println("TLS handshake complete!");
    Serial.print("Cipher: ");
    Serial.println(mbedtls_ssl_get_ciphersuite(&tls->ssl));

    return true;
}


// TLS write wrapper
int tls_write(tls_context_t *tls, const uint8_t *buf, size_t len)
{
    int ret;

    do {
        ret = mbedtls_ssl_write(&tls->ssl, buf, len);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
             ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    return ret;
}


// TLS read wrapper
int tls_read(tls_context_t *tls, uint8_t *buf, size_t len)
{
    int ret;
    int retry = 0;
    const int max_retries = 500;

    do {
        ret = mbedtls_ssl_read(&tls->ssl, buf, len);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            if (++retry > max_retries) {
                return MBEDTLS_ERR_SSL_WANT_READ;
            }
            delay(10);
        }
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
             ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    return ret;
}

// TLS close wrapper
void tls_close(tls_context_t *tls)
{    mbedtls_ssl_close_notify(&tls->ssl);
    mbedtls_ssl_free(&tls->ssl);
    mbedtls_ssl_config_free(&tls->conf);
    mbedtls_x509_crt_free(&tls->cacert);
}