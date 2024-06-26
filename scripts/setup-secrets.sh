#!/bin/bash

set -e

SECRETS_DIR=secrets

create_key_pair () {
  echo "generating keypair and certificate $1/$2 with CN:$3"
  openssl genrsa -out $1/$2.key 2048
  openssl rsa -in $1/$2.key -pubout > $1/$2.pub
  openssl req -new -sha256 \
    -key $1/$2.key \
    -subj "/C=US/CN=$3" \
    -out $1/$2.csr
  openssl x509 -req -days 500 -sha256 \
    -in $1/$2.csr \
    -CA $SECRETS_DIR/cacert.crt \
    -CAkey $SECRETS_DIR/cacert.key \
    -CAcreateserial \
    -out $1/$2.crt
  rm $1/$2.csr
}

mkdir -p ./$SECRETS_DIR
mkdir -p ./$SECRETS_DIR/oidc
mkdir -p ./$SECRETS_DIR/ssl

###
 # Create ca for local selfsigned certificates
###
if [[ ! -f $SECRETS_DIR/cacert.crt ]]; then
  openssl genrsa -out $SECRETS_DIR/cacert.key 4096
	openssl req -x509 -new -nodes -sha256 -days 1024 \
	  -key $SECRETS_DIR/cacert.key \
	  -out $SECRETS_DIR/cacert.crt \
	  -subj "/CN=US/CN=nl-rdo-uzipoc-oidc-provider-ca"
fi

###
# SSL certs
###
if [[ ! -f $SECRETS_DIR/ssl/server.crt ]]; then
  create_key_pair $SECRETS_DIR/ssl "server" "localhost"
fi

###
# nl-rdo-uzipoc-oidc-provider mock cert
###
if [[ ! -f $SECRETS_DIR/nl-rdo-uzipoc-oidc-provider.crt ]]; then
  create_key_pair $SECRETS_DIR "nl-rdo-uzipoc-oidc-provider" "nl-rdo-uzipoc-oidc-provider"
fi

###
# OIDC JWT signing
###
if [[ ! -f $SECRETS_DIR/oidc/selfsigned.crt ]]; then
  create_key_pair $SECRETS_DIR/oidc "selfsigned" "oidc_sign"
fi