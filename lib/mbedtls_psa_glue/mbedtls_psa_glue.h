#ifndef MBEDTLS_PSA_GLUE_H
#define MBEDTLS_PSA_GLUE_H

#ifdef __cplusplus
extern "C" {
#endif

int mbedtls_psa_get_random(void *p_rng, unsigned char *output, size_t output_len);

#ifdef __cplusplus
}
#endif

#endif // MBEDTLS_PSA_GLUE_H