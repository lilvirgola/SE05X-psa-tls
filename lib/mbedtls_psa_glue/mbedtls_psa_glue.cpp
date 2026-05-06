#include <Arduino.h>
#include "psa/crypto.h"

// use psa's random generator for mbedTLS entropy source
extern "C" int mbedtls_psa_get_random(void *p_rng, unsigned char *output, size_t output_len)
{
    (void)p_rng;
    Serial.print("Generating ");Serial.print(output_len);
    Serial.println(" random bytes for mbedTLS...");
    psa_status_t status = psa_generate_random(output, output_len);
    
    return (status == PSA_SUCCESS) ? 0 : -1;
}