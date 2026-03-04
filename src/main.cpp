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
#include "mbedtls/x509_crt.h"
#include "mbedtls/error.h"
#include "utils.h"
#include "test.h"
#include "mqtt.h"

const char ssid[] = SECRET_SSID;
const char pass[] = SECRET_PASS;
const char* mqtt_server = "10.30.20.210";  //MQTT broker IP
const int mqtt_port = 8883;  // MQTT over TLS port
const int mqtt_plain_port = 1883; // MQTT plain port
const char* mqtt_client_id = "portenta-se05x-client"; // MQTT client ID
const char* default_topic = "portenta/sensor"; // MQTT topic to subscribe/publish
String serial_input = "";
unsigned long last_ping = 0;
bool mqtt_tls_connected = false;

WiFiClient tcpClient;
PubSubClient mqttClient(tcpClient);

mbedtls_ssl_context ssl;
mbedtls_ssl_config conf;
mbedtls_x509_crt cacert;
mbedtls_x509_crt client_cert;
mbedtls_pk_context client_key;

psa_key_id_t key_id;


// Main setup

void setup()
{
    Serial.begin(115200);
    while (!Serial);
    // this reset is needed to ensure the SE05X is in a known state before starting the tests and demo
    Serial.println("=== SE05X Full Reset ===");
    
    if (SE05X.begin() != 1) {
        Serial.println("ERROR: SE05X initialization failed");
        while (1);
    }
    
    Serial.println("SE05X initialized");
    Serial.println("Deleting all objects...");
    
    if (SE05X.deleteAllObjects() == 1) {
        Serial.println("SUCCESS: All SE05X objects deleted");
    } else {
        Serial.println("WARNING: Delete all objects failed");
    }

    Serial.println("\n=== SE05X Hardware Crypto Test Suite ===\n");

    connect_wifi(ssid, pass);
    setup_psa_key(&key_id);
    
    test_random_generation();
    test_ecdsa_operations(&key_id);
    test_aes_operations();
    test_rsa_operations();
    Serial.println("\n=== All CryptoTests Complete ===");
    // Serial.println("\n=== HTTPS Connection Test ===\n");
    
    // if (!tcpClient.connect("www.google.com", 443))
    // {
    //     Serial.println("ERROR: TCP connection failed");
    //     while (1);
    // }

    // Serial.println("TCP connection established");
    // delay(100);

    // setup_tls(&tcpClient, &ssl, &conf, &cacert, wifi_send, wifi_recv);
    // perform_tls_handshake(&tcpClient, &ssl);
    // https_request(&ssl);
    // Serial.println("\n=== HTTPS Connection Test Complete ===");

    // Serial.println("Cleaning up HTTPS TLS context...");
    // mbedtls_ssl_close_notify(&ssl);
    // mbedtls_ssl_free(&ssl);
    // mbedtls_ssl_config_free(&conf);
    // mbedtls_x509_crt_free(&cacert);
    // tcpClient.stop();
    // Serial.println("Waiting for connection to fully close...");
    // delay(2000);

    Serial.println("\n=== SE05X MQTT Demo ===\n");
    // old plain MQTT connection - replaced by TLS connection below
    // connect_mqtt_plain(&tcpClient, mqtt_server, mqtt_plain_port, mqtt_client_id, default_topic, mqttClient);
    // handle_serial_input(mqttClient, default_topic);

    // Connect to MQTT with TLS
    mqtt_tls_connected = connect_mqtt_tls(
        &tcpClient,
        mqtt_server,
        mqtt_client_id,
        default_topic,
        mqtt_port,  // TLS port
        &ssl,
        &conf,
        &cacert,
        wifi_send,
        wifi_recv
    );
    
    if (!mqtt_tls_connected) {
        Serial.println("ERROR: MQTT-TLS connection failed");
        while (1);
    }
    Serial.println("\n=== Setup Complete ===");

    
}

void loop()
{
        if (!mqtt_tls_connected) {
        delay(1000);
        return;
    }
    
    // Handle incoming MQTT messages
    mqtt_tls_receive(&ssl);
    
    // Send PINGREQ every 30 seconds
    if (millis() - last_ping > 30000) {
        mqtt_tls_ping(&ssl);
        last_ping = millis();
    }
    
    // Handle serial input
    while (Serial.available()) {
        char c = Serial.read();
        
        if (c == '\n' || c == '\r') {
            if (serial_input.length() > 0) {
                // Publish message
                mqtt_tls_publish(&ssl, default_topic, serial_input.c_str());
                Serial.print("Published: ");
                Serial.println(serial_input);
                serial_input = "";
                Serial.print("> ");
            }
        } else {
            serial_input += c;
        }
    }
    
    delay(10);

    // old plain MQTT loop - replaced by mqtt callback and serial input handler in loop
    // if (mqttClient.connected())
    // {
    //     mqttClient.loop();
    //     handle_serial_input(mqttClient, default_topic);
    // }
    // else
    // {
    //     Serial.println("MQTT disconnected, attempting reconnect...");
    //     // connect_mqtt(&tcpClient, mqtt_server, mqtt_client_id,default_topic, mqtt_port, mqttClient, &ssl, &conf, &cacert, &client_cert, &client_key, wifi_send, wifi_recv);
    //     connect_mqtt_plain(&tcpClient, mqtt_server, mqtt_plain_port, mqtt_client_id, default_topic, mqttClient);

    //     delay(5000);
    // }
}