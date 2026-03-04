#ifndef UTILS_H
#define UTILS_H

#include <Arduino.h>
#include "WiFiC3.h"
#include "WiFiClient.h"
#include "IPAddress.h"
#include "arduino_secrets.h"
#include <PubSubClient.h>

void connect_wifi(const char *ssid, const char *pass);
void setup_psa_key(psa_key_id_t *key_id);
int wifi_send(void *ctx, const unsigned char *buf, size_t len);
int wifi_recv(void *ctx, unsigned char *buf, size_t len);
void process_serial_command(String command, PubSubClient &mqttClient, const char* default_topic);
void handle_serial_input(PubSubClient &mqttClient, const char* default_topic);
#endif // UTILS_H