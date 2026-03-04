#!/bin/bash

# Generate self-signed CA
openssl genrsa -out certs/ca.key 2048
openssl req -new -x509 -days 3650 -key certs/ca.key -out certs/ca.crt \
  -subj "/C=IT/ST=FVG/L=Udine/O=TestOrg/CN=MQTT CA"

# Generate server certificate
openssl genrsa -out certs/server.key 2048
openssl req -new -key certs/server.key -out certs/server.csr \
  -subj "/C=IT/ST=FVG/L=Udine/O=TestOrg/CN=localhost"
openssl x509 -req -in certs/server.csr -CA certs/ca.crt -CAkey certs/ca.key \
  -CAcreateserial -out certs/server.crt -days 365

# Set permissions
chmod 644 certs/ca.crt certs/server.crt
chmod 644 certs/ca.key certs/server.key

echo "Certificates generated in the certs/ directory"
echo "converting CA certificate to C header format..."
bash convert-cert.sh
echo "CA certificate converted to ca_cert.h"
echo "Copy this file to your Arduino project's include/ directory"