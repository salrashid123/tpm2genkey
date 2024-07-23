
## tpm2 key utility

Simple cli utility similar to [tpm2tss-genkey](https://github.com/tpm2-software/tpm2-tss-engine/blob/master/man/tpm2tss-genkey.1.md) which 

* creates new TPM-based `RSA|ECC` keys and saves the keys in `PEM` format.
* converts basic the public/private keyfiles generated using `tpm2_tools` into `PEM` file format.
* converts `PEM` TPM keyfiles to public/private structures readable by `tpm2_tools`.

The PEM output files are compliant with basic
[ASN.1 Specification for TPM 2.0 Key Files](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html) which is the format openssl (mostly) follows.

---

| Option | Description |
|:------------|-------------|
| **`-tpm-path`** | Path to the TPM device (default: `/dev/tpmrm0`) |
| **`-out`** | new key output PEM file (default: `private.pem`) |
| **`-alg`** | new key algorithm: rsa,ecdsa,aes (default: `rsa`) |
| **`-exponent`** | RSA exponent (default: `65537`) |
| **`-rsakeysize`** | RSA keysize: rsa (default: `2048`) |
| **`-curve`** | ECDSA curve (secp224r1|prime256v1|secp384r1|secp521r1) (default: `prime256v1`) |
| **`-mode`** | AES mode ([cfb|crt|ofb|cbc|ecb]) (default: `cfb`) |
| **`-aeskeysize`** | AES keysize: rsa (default: `128`) |
| **`-parent`** | key parent (default: `TPMRHOwner 0x40000001 // 1073741825`) |
| **`-password`** | passphrase for the TPM key (default: "") |
| **`-ownerpw`** | passphrase for the TPM owner (default: "") |
| **`-parentpw`** | passphrase for the TPM key parent (default: "") |
| **`-description`** | description field for the PEM encoded keyfile (default: "") |
| **`-in`** | input PEM key file to convert (default: `private.pem`) |
| **`-public`** | Public key (`TPM2B_PUBLIC`) to import or export (requires --private) (default: "") |
| **`-private`** | The (encrypted) private key (`TPM2B_PRIVATE`) to import or export. (requires --public) (default: "") |
| **`-help`** | print usage |


>> This repo is not supported by Google

---

### Build

You can use the binary in the `Releases` page as a standalone cli or load as a library or just build: 

```bash
go build -o tpm2genkey cmd/main.go
```

### New Key with PermanentHandle (TPMHTPermanent)

To create new TPM-based `RSA|ECC` key which uses the default `OWNER` and primary ["H2" template](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html#name-parent)


* `RSA` without userAuth:

```bash
  ### create an rsa key
  tpm2genkey --out=private.pem

  ### print the key details using openssl3 and tpm2-openssl
  openssl asn1parse -inform PEM -in private.pem
  openssl rsa -provider tpm2  -provider default -in private.pem --text
```

* `RSA` with userAuth

```bash
  tpm2genkey --out=private.pem --password=foo

  openssl rsa -provider tpm2  -provider default -in private.pem --text --passin pass:foo
```

* `ECDSA` wihout userAuth

```bash
  tpm2genkey --alg=ecdsa --out=private.pem

  openssl ec -provider tpm2  -provider default -in private.pem --text
```

* `AES`

```bash
  # generate the key
  tpm2genkey --alg=aes --mode=cfb --out=private.pem

  # use this same tool to convert the key to a format tpm2_tools understands
  tpm2genkey  --in=private.pem --public=key.pub --private=key.prv

  ### create the h2 template
  printf '\x00\x00' > /tmp/unique.dat
  tpm2_createprimary -C o -G ecc  -g sha256 \
      -c primary.ctx \
      -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u /tmp/unique.dat

  ### encrypt and decrypt
  echo "foo" > secret.dat
  openssl rand  -out iv.bin 16
  tpm2_load -C primary.ctx -u key.pub -r key.prv -c decrypt.ctx
  tpm2_encryptdecrypt --iv iv.bin -c decrypt.ctx -o encrypt.out secret.dat
  tpm2_encryptdecrypt --iv iv.bin -c decrypt.ctx  -d -o decrypt.out encrypt.out

  ## for set the keytype and then when encrypting/decrypting use --mode=cbc.  Since in this example the plaintext is small, 
  ## use --pad]
  # tpm2genkey --alg=aes --mode=cbc --out=/tmp/private.pem 
  # tpm2_encryptdecrypt --iv iv.bin -c decrypt.ctx --mode=cbc --pad -o encrypt.out secret.dat
```

note: Openssl does not implement encryption using a full TPM-resident key.  Instead, it just runs the encryption using a provided key (see [tpm2-openssl symmetric ciphers](https://github.com/tpm2-software/tpm2-openssl/blob/master/docs/symmetric.md#symmetric-ciphers))


### New Key with PersistentHandle (TPMHTPersistent)

If you want to genrate a key with a parent thats been saved to a persistent handle,

```bash
tpm2_createprimary -C o -c primary.ctx
tpm2_evictcontrol -C o -c primary.ctx 0x81010003

tpm2genkey --parent=0x81010003 --out=private.pem
```

---

### Convert [TPM2B_PUBLIC, TPM2B_PRIVATE] with TPMHTPermanent H2 Template --> PEM

`tpm2_tools` keys are encoded `[TPM2B_PUBLIC, TPM2B_PRIVATE]` structure format and not readable as PEM.  This script will convert them into PEM format.

Note, the default primary key below is the "h2" template as described in the [specifications](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html#name-parent)

```bash
# first create a primary using h2 template
printf '\x00\x00' > /tmp/unique.dat
tpm2_createprimary -C o -G ecc  -g sha256 \
    -c primary.ctx \
    -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u /tmp/unique.dat

# then an rsa key
tpm2_create -G rsa2048:rsassa:null -g sha256  -u key.pub -r key.prv -C primary.ctx

## convert to pem
tpm2genkey --public=key.pub --private=key.prv --out=private.pem
```

Note, if you have `tpm2tss-genkey` (openssl1.1) installed, you don't even need this library (you do if you have openssl3):

```bash
tpm2tss-genkey -u key.pub -r key.prv private.pem
```
 
### Convert [TPM2B_PUBLIC, TPM2B_PRIVATE] with TPMHTPersistent parent --> PEM  

THe following will create a parent, make it persistent (`0x81010003`), then this utility will covert the final key to PEM format

```bash
tpm2_createprimary -C o -c primary.ctx
tpm2_evictcontrol -C o -c primary.ctx 0x81010003
tpm2_create -G rsa2048:rsassa:null -g sha256  -u key.pub -r key.prv -C 0x81010003

# convert to pem
tpm2genkey --public=key.pub --private=key.prv --parent=0x81010003 --out=private.pem 
```

### Convert PEM --> [TPM2B_PUBLIC, TPM2B_PRIVATE]

To convert a PEM file to public/private keys:


```bash
## start with H2 primary
printf '\x00\x00' > /tmp/unique.dat
tpm2_createprimary -C o -G ecc  -g sha256 \
    -c primary.ctx \
    -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u /tmp/unique.dat

# then an rsa key
tpm2_create -G rsa2048:rsassa:null -g sha256  -u key.pub -r key.prv -C primary.ctx
tpm2_load -C primary.ctx -u key.pub -r key.prv -c key.ctx

## create private.pem from key.pub, key.prv
### using this cli
tpm2genkey  --public=key.pub --private=key.prv --out=private.pem
# or with openssl1.1 (since openssl3 does not support this conversion):  
# tpm2tss-genkey -u key.pub -r key.prv private.pem

# now convert private.pem to key2.pub, key2.prv
tpm2genkey --in=private.pem --public=key2.pub --private=key2.prv

### you may want to also print the key details using openssl which can give a hint about the
### primary (eg, if its a permanent handle, then probably regenerate  the 
###  h2 template itself i you don't have the primary.ctx handy
openssl asn1parse -inform PEM -in private.pem

## verify conversion by loading key2, you should see the same "name"
tpm2_load -C primary.ctx -u key2.pub -r key2.prv -c key2.ctx
```

### Appendix

#### OpenSSL TPM2 

If you intend to use openssl and TPMs, note that support is done with two different dependencies:

* openssl 1.1 [tpm2-tss-engine](https://github.com/tpm2-software/tpm2-tss-engine)

  Uses [tpm2tss-genkey](https://github.com/tpm2-software/tpm2-tss-engine/blob/master/man/tpm2tss-genkey.1.md)

* openssl 3 [tpm2-openssl](https://github.com/tpm2-software/tpm2-openssl)

  An openssl3 version of `tpm2tss-genkey` does not exist yet [issue17](https://github.com/tpm2-software/tpm2-openssl/issues/17) (which is partly why this repo is here)

The examples in this repo uses openssl3 (`tpm2-openssl`)

>> **NOTE**: openssl does *not* support parsing keys which includes [description](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html#name-description) parameter or when the [emptyAuth](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html#name-emptyauth) is omitted entirely from the encoded PEM (which according to the specs is intended to mean `emptyAuth=false`).  This is a defect with `tpm2-openssl` which will hopefully get fixed soon.  What this means until then is while you can use this utility to create well-formed keys, if they were created with `--description` or `--password`, openssl will either fail to parse them or detect if they key require userAuth.

#### SoftwareTPM

If you'd rather test with software tpm first,

```bash
rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm
sudo swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=5

## for tpm2_tools
export TPM2TOOLS_TCTI="swtpm:port=2321"
tpm2_pcrread sha256:23

## for openssl30
export TPM2OPENSSL_TCTI="swtpm:port=2321"

## then use this cli, set --tpm-path="127.0.0.1:2321"
tpm2genkey --alg=rsa --out=private.pem --tpm-path="127.0.0.1:2321"
```

