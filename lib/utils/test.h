#ifndef TEST_H
#define TEST_H
#include "WiFiClient.h"
#include "psa/crypto.h"

void test_random_generation();

void test_ecdsa_operations(psa_key_id_t *key_id);

void test_aes_operations();

void test_rsa_operations();

void test_ecdhe_operations();
#endif // TEST_H