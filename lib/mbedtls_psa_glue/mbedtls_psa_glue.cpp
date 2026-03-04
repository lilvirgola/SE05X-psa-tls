#include <Arduino.h>
#include "psa/crypto.h"

// use psa's random generator for mbedTLS entropy source (in this case, it will call SE05X's random function if available)
extern "C" int mbedtls_psa_get_random(void *p_rng, unsigned char *output, size_t output_len)
{
    (void)p_rng;  // Unused
    
    psa_status_t status = psa_generate_random(output, output_len);
    
    return (status == PSA_SUCCESS) ? 0 : -1;
}