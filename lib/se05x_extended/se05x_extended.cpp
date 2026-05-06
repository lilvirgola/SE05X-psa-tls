#include "se05x_extended.h"
#include "SE05X.h"
#include "se05x_types.h"

int se05x_extended::ECDH(uint32_t keyID,
                         const uint8_t* pubKey,
                         size_t pubKeyLen,
                         uint8_t* sharedSecret,
                         size_t* sharedSecretLen)
{
    if (!pubKey || !sharedSecret || !sharedSecretLen) {
        return 0;
    }

    smStatus_t status = Se05x_API_ECDHGenerateSharedSecret(
        getSession(),
        keyID,
        pubKey,
        pubKeyLen,
        sharedSecret,
        sharedSecretLen
    );

    return (status == SM_OK);
}
