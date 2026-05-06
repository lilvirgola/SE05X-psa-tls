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
#include "mbedtls/x509_crt.h"

#include "utils.h"
#include "test.h"
#include "mqtt.h"


// ===================== CONFIG =====================

const char ssid[] = SECRET_SSID;
const char pass[] = SECRET_PASS;

const char* mqtt_server = "10.42.0.1";
const int mqtt_port = 8883;

const char* mqtt_client_id = "portenta-se05x-client";
const char* default_topic = "portenta/sensor";


// ===================== GLOBALS =====================

WiFiClient tcpClient;
tls_context_t tls;

psa_key_id_t key_id;

String serial_input = "";
unsigned long last_ping = 0;
bool mqtt_tls_connected = false;


// ===================== SETUP =====================

void setup()
{
    Serial.begin(115200);
    while (!Serial);

    Serial.println("=== SE05X Reset ===");

    if (SE05X.begin() != 1) {
        Serial.println("SE05X init failed");
        while (1);
    }

    Serial.println("SE05X ready");

    if (SE05X.deleteAllObjects() == 1) {
        Serial.println("SE05X cleared");
    } else {
        Serial.println("Could not clear SE05X");
    }

    // --- WIFI ---
    connect_wifi(ssid, pass);

    // --- PSA / KEY ---
    setup_psa_key(&key_id);

    // --- CRYPTO TESTS ---
    Serial.println("\n=== Crypto tests ===\n");
    test_random_generation();
    test_ecdsa_operations(&key_id);
    test_aes_operations();
    test_rsa_operations();
    test_ecdhe_operations();
    Serial.println("\nCrypto tests done");

    // --- TLS + MQTT ---
    Serial.println("\n=== MQTT over TLS ===\n");

    while (!mqtt_tls_connected)
    {
        mqtt_tls_connected = connect_mqtt_tls(
            &tcpClient,
            mqtt_server,
            mqtt_client_id,
            default_topic,
            mqtt_port,
            &tls,
            wifi_send,
            wifi_recv
        );

        if (!mqtt_tls_connected) {
            Serial.println("MQTT TLS connection failed, retrying...");
            delay(2000);
        }
    }

    Serial.println("Setup complete");
    Serial.print("> ");
}


// ===================== LOOP =====================

unsigned long last_reconnect_attempt = 0;
const unsigned long reconnect_interval = 2000;

void loop() {
    Serial.println("\n--- Main loop ---");

    // --- RECONNECT ---
    if (!mqtt_tls_connected && millis() - last_reconnect_attempt > reconnect_interval) {
        mqtt_tls_connected = connect_mqtt_tls(
            &tcpClient,
            mqtt_server,
            mqtt_client_id,
            default_topic,
            mqtt_port,
            &tls,
            wifi_send,
            wifi_recv
        );

        last_reconnect_attempt = millis();

        if (mqtt_tls_connected) {
            Serial.println("MQTT TLS connected");
        } else {
            Serial.println("MQTT TLS connection failed, will retry...");
        }
    }

    // --- RECEIVE MQTT ---
    if (mqtt_tls_connected) {
        mqtt_tls_receive(&tls);
    }

    // --- KEEPALIVE ---
    if (mqtt_tls_connected && millis() - last_ping > 30000) {
        mqtt_tls_ping(&tls);
        last_ping = millis();
    }

    // user input from serial to publish MQTT messages
    // while (Serial.available()) {
    //     char c = Serial.read();
    //     if (c == '\n' || c == '\r') {
    //         if (serial_input.length() > 0) {
    //             if (mqtt_tls_connected)
    //                 mqtt_tls_publish(&tls, default_topic, serial_input.c_str());

    //             Serial.print("Published: ");
    //             Serial.println(serial_input);

    //             serial_input = "";
    //             Serial.print("> ");
    //         }
    //     } else {
    //         serial_input += c;
    //     }
    // }
}