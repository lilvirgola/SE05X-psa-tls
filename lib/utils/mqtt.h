#ifndef _MQTT_H
#define _MQTT_H

#include "WiFiClient.h"
#include "PubSubClient.h"
#include "psa_se05x_wrapper.h"
#include "utils.h"

void mqtt_tls_receive(tls_context_t *ssl);
void mqtt_tls_ping(tls_context_t *ssl);
bool mqtt_tls_publish(tls_context_t *ssl, const char *topic, const char *message);

void mqtt_callback(char* topic, byte* payload, unsigned int length);

bool connect_mqtt_tls(
    WiFiClient *tcpClient,
    const char *mqtt_server,
    const char *mqtt_client_id,
    const char *default_topic,
    int mqtt_port,
    tls_context_t *tls,
    int (*wifi_send)(void *ctx, const unsigned char *buf, size_t len),
    int (*wifi_recv)(void *ctx, unsigned char *buf, size_t len));

bool connect_mqtt_plain(
    WiFiClient *tcpClient, 
    const char *mqtt_server,
    int mqtt_plain_port, 
    const char *mqtt_client_id, 
    const char *default_topic,
    PubSubClient &mqttClient);

#endif // _MQTT_H