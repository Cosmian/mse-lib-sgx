# MicroService Encryption Lib SGX

## Overview

MSE lib SGX bootstraps the execution of an encrypted ASGI/WSGI Python web application for [Gramine](https://gramine.readthedocs.io/).

The library is responsible for:

- Configuring the SSL certificates with either:
  - *RA-TLS*, a self-signed certificate including the Intel SGX quote in an X.509 v3 extension
  - *Custom*, the private key and full keychain is provided by the application owner
  - *No SSL*, the secure channel may be managed elsewhere by an SSL proxy
- Decrypting Python modules encrypted with XSala20-Poly1305 AEAD
- Running the ASGI/WSGI Python web application with [hypercorn](https://pgjones.gitlab.io/hypercorn/)

## Technical details

The flow to run an encrypted Python web application is the following:

1. A first self-signed HTTPS server using RA-TLS is launched waiting to receive a JSON payload with:
   - UUID, a unique application identifier provided to `mse-bootstrap` as an argument
   - the decryption key of the code
   - Optionally the private key corresponding to the certificate provided to `mse-bootstrap` (for *Custom* certificate)
2. If the UUID and decryption key are the expected one, the configuration server is stopped, the code is decrypted and finally run as a new server


## Installation 

```console
$ pip install mse-lib-sgx
```

## Usage

```console
$ mse-bootstrap --help
usage: mse-bootstrap [-h] --host HOST --port PORT --app-dir APP_DIR --uuid UUID [--version]
                     [--debug]
                     (--self-signed EXPIRATION_DATE | --no-ssl | --certificate CERTIFICATE_PATH)
                     application

Bootstrap ASGI/WSGI Python web application for Gramine

positional arguments:
  application           Application to dispatch to as path.to.module:instance.path

optional arguments:
  -h, --help            show this help message and exit
  --host HOST           Hostname of the configuration serverIf `--self-signed`, it's also the
                        hostname of the app server
  --port PORT           Port of the server
  --app-dir APP_DIR     Path the microservice application. Read only directory.
  --uuid UUID           Unique application UUID.
  --version             show program's version number and exit
  --debug               Debug mode without SGX
  --self-signed EXPIRATION_DATE
                        Generate a self-signed certificate for the app. Specify the expiration
                        date of the certificate as a timestamp since Epoch
  --no-ssl              Don't use HTTPS connection
  --certificate CERTIFICATE_PATH
                        Use the given certificate for the SSL connection. the private key will
                        be sent using the configuration server

```
