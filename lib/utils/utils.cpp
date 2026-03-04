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

// String serial_buffer = "";
// bool message_ready = false;

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
    Serial.println("Connecting to WiFi...");

    while (WiFi.begin(ssid, pass) != WL_CONNECTED)
    {
        delay(3000);
        Serial.println("Retrying WiFi connection...");
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
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_id(&attr, *key_id);
    psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_PERSISTENT);

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


// Process serial commands

// void process_serial_command(String command, PubSubClient &mqttClient, const char* default_topic)
// {
//     command.trim();
    
//     if (command.length() == 0)
//     {
//         return;
//     }
    
//     // Check for special commands
//     if (command.startsWith("/"))
//     {
//         if (command.equals("/help"))
//         {
//             Serial.println("\n--- Available Commands ---");
//             Serial.println("Type any message to publish to default topic");
//             Serial.println("/help                 - Show this help");
//             Serial.println("/status               - Show connection status");
//             Serial.println("/pub <topic> <msg>    - Publish to specific topic");
//             Serial.println("/sub <topic>          - Subscribe to topic");
//             Serial.println("/unsub <topic>        - Unsubscribe from topic");
//             Serial.println("---------------------------\n");
//         }
//         else if (command.equals("/status"))
//         {
//             Serial.println("\n--- Status ---");
//             Serial.print("WiFi: ");
//             Serial.println(WiFi.status() == WL_CONNECTED ? "Connected" : "Disconnected");
//             Serial.print("MQTT: ");
//             Serial.println(mqttClient.connected() ? "Connected" : "Disconnected");
//             Serial.print("Default topic: ");
//             Serial.println(default_topic);
//             Serial.println("--------------\n");
//         }
//         else if (command.startsWith("/pub "))
//         {
//             int first_space = command.indexOf(' ', 5);
//             if (first_space > 0)
//             {
//                 String topic = command.substring(5, first_space);
//                 String message = command.substring(first_space + 1);
                
//                 if (mqttClient.publish(topic.c_str(), message.c_str()))
//                 {
//                     Serial.print("Published to ");
//                     Serial.print(topic);
//                     Serial.print(": ");
//                     Serial.println(message);
//                 }
//                 else
//                 {
//                     Serial.println("ERROR: Publish failed");
//                 }
//             }
//             else
//             {
//                 Serial.println("ERROR: Usage - /pub <topic> <message>");
//             }
//         }
//         else if (command.startsWith("/sub "))
//         {
//             String topic = command.substring(5);
//             topic.trim();
            
//             if (mqttClient.subscribe(topic.c_str()))
//             {
//                 Serial.print("Subscribed to: ");
//                 Serial.println(topic);
//             }
//             else
//             {
//                 Serial.println("ERROR: Subscribe failed");
//             }
//         }
//         else if (command.startsWith("/unsub "))
//         {
//             String topic = command.substring(7);
//             topic.trim();
            
//             if (mqttClient.unsubscribe(topic.c_str()))
//             {
//                 Serial.print("Unsubscribed from: ");
//                 Serial.println(topic);
//             }
//             else
//             {
//                 Serial.println("ERROR: Unsubscribe failed");
//             }
//         }
//         else
//         {
//             Serial.println("Unknown command. Type /help for available commands.");
//         }
//     }
//     else
//     {
//         // Publish to default topic
//         if (mqttClient.publish(default_topic, command.c_str()))
//         {
//             Serial.print("Published: ");
//             Serial.println(command);
//         }
//         else
//         {
//             Serial.println("ERROR: Publish failed");
//         }
//     }
// }


// void handle_serial_input(PubSubClient &mqttClient, const char* default_topic)
// {
//     while (Serial.available() > 0)
//     {
//         char c = Serial.read();
        
//         if (c == '\n' || c == '\r')
//         {
//             if (serial_buffer.length() > 0)
//             {
//                 message_ready = true;
//             }
//         }
//         else
//         {
//             serial_buffer += c;
//         }
//     }
    
//     if (message_ready)
//     {
//         process_serial_command(serial_buffer, mqttClient, default_topic);
//         serial_buffer = "";
//         message_ready = false;
//         Serial.print("> ");
//     }
// }