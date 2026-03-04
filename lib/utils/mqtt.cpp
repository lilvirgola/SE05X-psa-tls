#include <Arduino.h>
#include <WiFiC3.h>
#include <WiFiClient.h>
#include <PubSubClient.h>
#include "arduino_secrets.h"
#include "ca_cert.h"
#include "psa_se05x_wrapper.h"
#include "mbedtls_psa_glue.h"

#include "psa/crypto.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/error.h"
#include "mbedtls/pk.h"



// MQTT callback

void mqtt_callback(char* topic, byte* payload, unsigned int length)
{
    Serial.println("\n--- Incoming Message ---");
    Serial.print("Topic: ");
    Serial.println(topic);
    Serial.print("Payload: ");
    for (unsigned int i = 0; i < length; i++)
    {
        Serial.print((char)payload[i]);
    }
    Serial.println();
    Serial.println("------------------------");
}

// MQTT connection

bool connect_mqtt_plain(
    WiFiClient *tcpClient, 
    const char *mqtt_server,
    int mqtt_plain_port, 
    const char *mqtt_client_id, 
    const char *default_topic,
    PubSubClient &mqttClient)
{
    Serial.println("\n--- MQTT Connection (Plain) ---");
    
    mqttClient.setServer(mqtt_server, mqtt_plain_port);  // Plain MQTT port
    mqttClient.setClient(*tcpClient);
    mqttClient.setCallback(mqtt_callback);
    
    if (mqttClient.connect(mqtt_client_id))
    {
        Serial.println("Connected to MQTT broker");
        
        if (mqttClient.subscribe(default_topic))
        {
            Serial.println("Subscribed to topic");
        }
        
        return true;
    }
    else
    {
        Serial.print("MQTT connection failed, state: ");
        Serial.println(mqttClient.state());
        return false;
    }
}

// MQTT connection with TLS

// MQTT packet construction helpers

void mqtt_write_string(uint8_t *buf, int *pos, const char *str)
{
    int len = strlen(str);
    buf[(*pos)++] = (len >> 8) & 0xFF;
    buf[(*pos)++] = len & 0xFF;
    memcpy(&buf[*pos], str, len);
    *pos += len;
}

void mqtt_write_byte(uint8_t *buf, int *pos, uint8_t byte)
{
    buf[(*pos)++] = byte;
}

void mqtt_write_uint16(uint8_t *buf, int *pos, uint16_t value)
{
    buf[(*pos)++] = (value >> 8) & 0xFF;
    buf[(*pos)++] = value & 0xFF;
}

// MQTT CONNECT packet
int mqtt_create_connect(uint8_t *buf, const char *client_id, uint16_t keepalive)
{
    int pos = 0;
    
    // Fixed header
    mqtt_write_byte(buf, &pos, 0x10);  // CONNECT packet type
    
    // Calculate remaining length (we'll update this)
    int remaining_length_pos = pos;
    mqtt_write_byte(buf, &pos, 0);  // Placeholder
    
    int payload_start = pos;
    
    // Variable header
    mqtt_write_string(buf, &pos, "MQTT");  // Protocol name
    mqtt_write_byte(buf, &pos, 0x04);      // Protocol level (3.1.1)
    mqtt_write_byte(buf, &pos, 0x02);      // Connect flags (clean session)
    mqtt_write_uint16(buf, &pos, keepalive);
    
    // Payload
    mqtt_write_string(buf, &pos, client_id);
    
    // Update remaining length
    buf[remaining_length_pos] = pos - payload_start;
    
    return pos;
}

// MQTT SUBSCRIBE packet
int mqtt_create_subscribe(uint8_t *buf, const char *topic, uint16_t packet_id)
{
    int pos = 0;
    
    // Fixed header
    mqtt_write_byte(buf, &pos, 0x82);  // SUBSCRIBE packet type with QoS 1
    
    int remaining_length_pos = pos;
    mqtt_write_byte(buf, &pos, 0);
    
    int payload_start = pos;
    
    // Variable header
    mqtt_write_uint16(buf, &pos, packet_id);
    
    // Payload
    mqtt_write_string(buf, &pos, topic);
    mqtt_write_byte(buf, &pos, 0x00);  // QoS 0
    
    buf[remaining_length_pos] = pos - payload_start;
    
    return pos;
}

// MQTT PUBLISH packet
int mqtt_create_publish(uint8_t *buf, const char *topic, const char *message)
{
    int pos = 0;
    
    // Fixed header
    mqtt_write_byte(buf, &pos, 0x30);  // PUBLISH packet type, QoS 0
    
    int remaining_length_pos = pos;
    mqtt_write_byte(buf, &pos, 0);
    
    int payload_start = pos;
    
    // Variable header
    mqtt_write_string(buf, &pos, topic);
    
    // Payload
    int msg_len = strlen(message);
    memcpy(&buf[pos], message, msg_len);
    pos += msg_len;
    
    buf[remaining_length_pos] = pos - payload_start;
    
    return pos;
}

// MQTT PINGREQ packet
int mqtt_create_pingreq(uint8_t *buf)
{
    buf[0] = 0xC0;  // PINGREQ
    buf[1] = 0x00;  // Remaining length = 0
    return 2;
}

// Parse incoming MQTT packet
void mqtt_parse_packet(uint8_t *buf, int len)
{
    if (len < 2) return;
    
    uint8_t packet_type = buf[0] & 0xF0;
    
    switch (packet_type) {
        case 0x20: // CONNACK
            if (buf[3] == 0x00) {
                Serial.println("MQTT: CONNACK received - Connected!");
            } else {
                Serial.print("MQTT: CONNACK error code: ");
                Serial.println(buf[3]);
            }
            break;
            
        case 0x30: // PUBLISH
            {
                int pos = 2;
                // Topic length
                uint16_t topic_len = (buf[pos] << 8) | buf[pos + 1];
                pos += 2;
                
                // Topic
                char topic[128];
                memcpy(topic, &buf[pos], topic_len);
                topic[topic_len] = 0;
                pos += topic_len;
                
                // Message
                int msg_len = len - pos;
                char message[256];
                memcpy(message, &buf[pos], msg_len);
                message[msg_len] = 0;
                
                Serial.println("\n--- Incoming MQTT Message ---");
                Serial.print("Topic: ");
                Serial.println(topic);
                Serial.print("Message: ");
                Serial.println(message);
                Serial.println("-----------------------------");
                Serial.print("> ");
            }
            break;
            
        case 0x90: // SUBACK
            Serial.println("MQTT: SUBACK received - Subscribed!");
            break;
            
        case 0xD0: // PINGRESP
            // Silent - this is just keepalive
            break;
            
        default:
            Serial.print("MQTT: Unknown packet type: 0x");
            Serial.println(packet_type, HEX);
            break;
    }
}

// Main MQTT-TLS connection function
bool connect_mqtt_tls(
    WiFiClient *tcpClient,
    const char *mqtt_server,
    const char *mqtt_client_id,
    const char *default_topic,
    int mqtt_port,
    mbedtls_ssl_context *ssl,
    mbedtls_ssl_config *conf,
    mbedtls_x509_crt *cacert,
    int (*wifi_send)(void *ctx, const unsigned char *buf, size_t len),
    int (*wifi_recv)(void *ctx, unsigned char *buf, size_t len))
{
    Serial.println("\n=== MQTT over TLS Connection ===");
    
    // TCP connect
    Serial.print("Connecting to ");
    Serial.print(mqtt_server);
    Serial.print(":");
    Serial.println(mqtt_port);
    
    if (!tcpClient->connect(mqtt_server, mqtt_port)) {
        Serial.println("ERROR: TCP connection failed");
        return false;
    }
    
    Serial.println("TCP connected");
    delay(200);
    
    // TLS setup
    Serial.println("Setting up TLS...");
    
    mbedtls_ssl_init(ssl);
    mbedtls_ssl_config_init(conf);
    mbedtls_x509_crt_init(cacert);
    
    // Load CA certificate
    int ret = mbedtls_x509_crt_parse(cacert, (const unsigned char*)ca_cert_pem, ca_cert_pem_len);
    if (ret != 0) {
        Serial.print("ERROR: CA cert parse failed: 0x");
        Serial.println(-ret, HEX);
        return false;
    }
    
    ret = mbedtls_ssl_config_defaults(
        conf,
        MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT);
    
    if (ret != 0) {
        Serial.print("ERROR: SSL config failed: 0x");
        Serial.println(-ret, HEX);
        return false;
    }
    
    // Disable cert verification for now (we'll fix the cert later)
    mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_NONE);
    
    // Use hardware-backed RNG from SE05X
    Serial.println("Configuring SE05X hardware RNG...");
    mbedtls_ssl_conf_rng(conf, mbedtls_psa_get_random, NULL);
    
    ret = mbedtls_ssl_setup(ssl, conf);
    if (ret != 0) {
        Serial.print("ERROR: SSL setup failed: 0x");
        Serial.println(-ret, HEX);
        return false;
    }
    
    mbedtls_ssl_set_hostname(ssl, mqtt_server);
    mbedtls_ssl_set_bio(ssl, tcpClient, wifi_send, wifi_recv, NULL);
    
    // TLS handshake
    Serial.println("Starting TLS handshake...");
    int retry = 0;
    while ((ret = mbedtls_ssl_handshake(ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
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
    Serial.println(mbedtls_ssl_get_ciphersuite(ssl));
    Serial.println("Using SE05X hardware random number generator");
    
    // Send MQTT CONNECT
    Serial.println("Sending MQTT CONNECT...");
    uint8_t connect_packet[128];
    int connect_len = mqtt_create_connect(connect_packet, mqtt_client_id, 60);
    
    ret = mbedtls_ssl_write(ssl, connect_packet, connect_len);
    if (ret < 0) {
        Serial.print("ERROR: Failed to send CONNECT: 0x");
        Serial.println(-ret, HEX);
        return false;
    }
    
    // Wait for CONNACK
    Serial.println("Waiting for CONNACK...");
    uint8_t response[256];
    retry = 0;

    while (retry < 100) {
        ret = mbedtls_ssl_read(ssl, response, sizeof(response));
        
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            // No data yet, keep waiting
            delay(10);
            retry++;
            continue;
        }
        
        if (ret < 0) {
            Serial.print("ERROR: Failed to read CONNACK: 0x");
            Serial.println(-ret, HEX);
            return false;
        }
        
        if (ret > 0) {
            // Got CONNACK
            mqtt_parse_packet(response, ret);
            break;
        }
    }

    if (retry >= 100) {
        Serial.println("ERROR: Timeout waiting for CONNACK");
        return false;
    }

    
    // Subscribe to topic
    Serial.print("Subscribing to: ");
    Serial.println(default_topic);
    uint8_t subscribe_packet[128];
    int subscribe_len = mqtt_create_subscribe(subscribe_packet, default_topic, 1);
    
    ret = mbedtls_ssl_write(ssl, subscribe_packet, subscribe_len);
    if (ret < 0) {
        Serial.print("ERROR: Failed to send SUBSCRIBE: 0x");
        Serial.println(-ret, HEX);
        return false;
    }
    
    // Wait for SUBACK
    ret = mbedtls_ssl_read(ssl, response, sizeof(response));
    if (ret > 0) {
        mqtt_parse_packet(response, ret);
    }
    
    Serial.println("\n=== MQTT-TLS Connected ===");
    Serial.println("Type messages to publish");
    Serial.print("> ");
    
    return true;
}

// MQTT-TLS publish function
bool mqtt_tls_publish(mbedtls_ssl_context *ssl, const char *topic, const char *message)
{
    uint8_t publish_packet[512];
    int publish_len = mqtt_create_publish(publish_packet, topic, message);
    
    int ret = mbedtls_ssl_write(ssl, publish_packet, publish_len);
    if (ret < 0) {
        Serial.print("ERROR: Publish failed: 0x");
        Serial.println(-ret, HEX);
        return false;
    }
    
    return true;
}

// MQTT-TLS receive function (non-blocking)
void mqtt_tls_receive(mbedtls_ssl_context *ssl)
{
    uint8_t response[512];
    
    int ret = mbedtls_ssl_read(ssl, response, sizeof(response));
    
    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        // No data available - this is normal
        return;
    }
    
    if (ret < 0) {
        Serial.print("ERROR: Read failed: 0x");
        Serial.println(-ret, HEX);
        return;
    }
    
    if (ret > 0) {
        mqtt_parse_packet(response, ret);
    }
}

// Send PINGREQ for keepalive
void mqtt_tls_ping(mbedtls_ssl_context *ssl)
{
    uint8_t ping_packet[2];
    mqtt_create_pingreq(ping_packet);
    mbedtls_ssl_write(ssl, ping_packet, 2);
}