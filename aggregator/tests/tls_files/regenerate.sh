#!/bin/bash
CAROOT=. mkcert -ecdsa -cert-file 127.0.0.1.pem -key-file 127.0.0.1-key.pem 127.0.0.1

