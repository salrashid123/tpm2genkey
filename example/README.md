
### Setup

```bash
rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm  && \
    swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert && \
    swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=2

export TPM2TOOLS_TCTI="swtpm:port=2321"
export TPM2OPENSSL_TCTI="swtpm:port=2321"
export OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules/

tpm2_flushcontext -t &&  tpm2_flushcontext -s  &&  tpm2_flushcontext -l

tpm2_pcrextend 23:sha256=0x0000000000000000000000000000000000000000000000000000000000000000
tpm2_pcrread sha256:23
  sha256:
    23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B
```

### With Basic

The following does not encode the policy into the PEM...the user needs to know that the key encodes policies and what is needed to fulfill that

```bash
## no passphrase:
go run cmd/main.go --mode=create --alg=rsa --out=/tmp/private.pem --tpm-path="127.0.0.1:2321"

cd example/
go run basic/main.go --keyfile=/tmp/private.pem --tpm-path="127.0.0.1:2321"


## passphrase:
go run cmd/main.go --mode=create --alg=rsa --out=/tmp/private.pem --tpm-path="127.0.0.1:2321" --password=foo

cd example/
go run basic/main.go --keyfile=/tmp/private.pem --tpm-path="127.0.0.1:2321" --password=foo


## passphrase and PCR:
go run cmd/main.go --mode=create --alg=rsa --out=/tmp/private.pem --tpm-path="127.0.0.1:2321" --password=foo --pcrs=23 

cd example/
go run basic/main.go --keyfile=/tmp/private.pem --tpm-path="127.0.0.1:2321"  --password=foo --pcrs=23 
```


### With PolicySyntax

The following uses the encoded policy structure in the PEM to construct the required commands.

```bash
## no passphrase:
go run cmd/main.go --mode=create --alg=rsa --out=/tmp/private.pem --tpm-path="127.0.0.1:2321"

cd example/
go run policysyntax/main.go --keyfile=/tmp/private.pem --tpm-path="127.0.0.1:2321"


## passphrase:
go run cmd/main.go --mode=create --alg=rsa --out=/tmp/private.pem --tpm-path="127.0.0.1:2321" --password=foo -enablePolicySyntax

cd example/
go run policysyntax/main.go --keyfile=/tmp/private.pem --tpm-path="127.0.0.1:2321" --password=foo


## passphrase and PCR:
go run cmd/main.go --mode=create --alg=rsa --out=/tmp/private.pem --tpm-path="127.0.0.1:2321" --password=foo --pcrs=23 -enablePolicySyntax

cd example/
go run policysyntax/main.go --keyfile=/tmp/private.pem --tpm-path="127.0.0.1:2321"  --password=foo
```

### LoadExternal

The `--loadexternal` will attempt to load an external RSA  or ECC key and get its 'name'

The usecase for this is to address loading EK RSA key with a specific exponent value ([see tpm2-tools/issues/3508](https://github.com/tpm2-software/tpm2-tools/issues/3508))

```bash
### create the ekrsa
swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 \
   --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=2

export TPM2TOOLS_TCTI="swtpm:port=2321"

tpm2_createek -c /tmp/ek.ctx -G rsa -u /tmp/ek.pub 
tpm2_readpublic -c /tmp/ek.ctx -o /tmp/ek.pem -f PEM -n /tmp/ek.name

## note the 'name' is different if we try to load the key
tpm2_loadexternal -C o -g sha256 -G rsa2048:null:aes128cfb  -u /tmp/ek.pem \
   -c /tmp/newparent.ctx    --policy=837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa  \
   --attributes="fixedtpm|fixedparent|sensitivedataorigin|adminwithpolicy|restricted|decrypt" --rsa_exponent_zero

   name: 000bfac0f9e26465941b3bce3bec267bec77c04293d2b930d673e37feff675e77dd5
```

So using this utility, specify the exponent and we'll get the corrent 'name' and export the public as `TPM2B_PUBLIC` to a file
for later use

```bash
$ go run cmd/main.go --mode=loadexternal --parentKeyType=ek_rsa --in=/tmp/ek.pem \
    --public=/tmp/pub.dat --exponent=0 \
    --tpm-path="127.0.0.1:2321"

   loaded name 000bfac0f9e26465941b3bce3bec267bec77c04293d2b930d673e37feff675e77dd5
```
