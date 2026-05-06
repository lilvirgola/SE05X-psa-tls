#ifndef UTILS_H
#define UTILS_H

#include <Arduino.h>
#include "WiFiC3.h"
#include "WiFiClient.h"
#include "IPAddress.h"
#include "arduino_secrets.h"
#include <PubSubClient.h>
#include "mbedtls/ssl.h"

typedef struct {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
} tls_context_t;

void connect_wifi(const char *ssid, const char *pass);
void setup_psa_key(psa_key_id_t *key_id);
int wifi_send(void *ctx, const unsigned char *buf, size_t len);
int wifi_recv(void *ctx, unsigned char *buf, size_t len);
void process_serial_command(String command, PubSubClient &mqttClient, const char* default_topic);
void handle_serial_input(PubSubClient &mqttClient, const char* default_topic);
bool tls_connect(tls_context_t *tls, WiFiClient *tcpClient, const char *hostname, int port, const unsigned char *ca_cert, size_t ca_cert_len);
int tls_write(tls_context_t *tls, const uint8_t *buf, size_t len);
int tls_read(tls_context_t *tls, uint8_t *buf, size_t len);
void tls_close(tls_context_t *tls);
#endif // UTILS_H