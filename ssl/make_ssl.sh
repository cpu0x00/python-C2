#!/bin/bash

echo 'press ENTER in all input fields'

openssl req -new -x509 -nodes -out c2server.crt -keyout c2server.key

echo "[*] generated a certificate and a private key"
echo "[*] merging the both..."

cat c2server.crt >> c2server.key

echo '[*] done, merged in (c2server.key) file.'

rm c2server.crt
