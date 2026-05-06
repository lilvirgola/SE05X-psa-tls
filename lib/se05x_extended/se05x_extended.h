#ifndef SE05X_EXTENDED_H
#define SE05X_EXTENDED_H
#include "SE05X.h"
#include "se05x_types.h"

class se05x_extended : public SE05XClass
{
public:
    int ECDH(uint32_t keyID,
             const uint8_t* pubKey,
             size_t pubKeyLen,
             uint8_t* sharedSecret,
             size_t* sharedSecretLen);
};
#endif // SE05X_EXTENDED_H