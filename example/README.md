
### Setup

```bash
rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm  && \
    sudo swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert && \
    sudo swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=2

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
