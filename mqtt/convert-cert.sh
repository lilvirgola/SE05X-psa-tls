#!/bin/bash

echo '#ifndef CA_CERT_H' > ca_cert.h
echo '#define CA_CERT_H' >> ca_cert.h
echo '' >> ca_cert.h
echo 'const char ca_cert_pem[] = ' >> ca_cert.h
cat certs/ca.crt | sed 's/^/"/' | sed 's/$/\\n"/' >> ca_cert.h
echo ';' >> ca_cert.h
echo '' >> ca_cert.h
echo 'const size_t ca_cert_pem_len = sizeof(ca_cert_pem);' >> ca_cert.h
echo '' >> ca_cert.h
echo '#endif' >> ca_cert.h