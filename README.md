
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
| **`-mode`** | Operation mode: [`create tpm2pem pem2tpm`] (default: ``) |
| **`-out`** | new key output PEM file (default: `private.pem`) |
| **`-alg`** | new key algorithm: [`rsa ecdsa aes hmac`] (default: `rsa`) |
| **`-exponent`** | RSA exponent (default: `65537`) |
| **`-rsakeysize`** | RSA keysize: rsa (default: `2048`) |
| **`-curve`** | ECDSA curve (`secp224r1 prime256v1 secp384r1 secp521r1`) (default: `prime256v1`) |
| **`-aesmode`** | AES mode ([`cfb crt ofb cbc ecb`]) (default: `cfb`) |
| **`-aeskeysize`** | AES keysize: rsa (default: `128`) |
| **`-parent`** | key parent (default: `TPMRHOwner 0x40000001 // 1073741825`) |
| **`-password`** | passphrase for the TPM key (default: "") |
| **`-ownerpw`** | passphrase for the TPM owner (default: "") |
| **`-parentpw`** | passphrase for the TPM key parent (default: "") |
| **`-description`** | description field for the PEM encoded keyfile (default: "") |
| **`-pcrs`** | comma separated list of current pcr values to bind the key to (default: "") |
| **`-commandCodePolicy`** | (tpm2pem) comma separated list of commandCode and hexPolicy command1:policy1,command2:policy2 (default: "") |
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

To create new TPM-based `RSA|ECC|AES|HMAC` key which uses the default `OWNER` and primary ["H2" template](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html#name-parent)


* `RSA` without userAuth:

```bash
  ### create an rsa key
  tpm2genkey  --mode=create --alg=rsa --out=private.pem

  ### if you have openssl3 tpm2 installed https://github.com/tpm2-software/tpm2-openssl
  # you can print the key details for the swtpm
  # export OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules/
  # export TPM2OPENSSL_TCTI="swtpm:port=2321"

  # openssl asn1parse -inform PEM -in private.pem
  # openssl rsa -provider tpm2  -provider default -in private.pem --text
```

* `RSA` with userAuth

```bash
  tpm2genkey --mode=create --alg=rsa --out=private.pem --password=foo

  openssl rsa -provider tpm2  -provider default -in private.pem --text --passin pass:foo
```

* `RSA` with PCR

```bash
  tpm2genkey --mode=create --alg=rsa --out=private.pem --pcrs=23 
```

* `RSA` with PCR and Password

```bash
  tpm2genkey --mode=create --alg=rsa --out=private.pem --password=foo --pcrs=23 
```

* `ECDSA` wihout userAuth

```bash
  tpm2genkey  --mode=create --alg=ecdsa --out=private.pem

  openssl ec -provider tpm2  -provider default -in private.pem --text
```

* `AES`

```bash
  # generate the key
  tpm2genkey  --mode=create --alg=aes --aesmode=cfb --out=private.pem
```

* `HMAC`

HMAC key generation on TPM:


```bash
  # generate the key
  tpm2genkey --mode=create --alg=hmac  --out=private.pem 
```

### New Key with PersistentHandle (TPMHTPersistent)

If you want to generate a key with a parent thats been saved to a persistent handle,

```bash
tpm2_createprimary -C o -c primary.ctx
tpm2_evictcontrol -C o -c primary.ctx 0x81010003

tpm2genkey --mode=create --alg=rsa  --parent=0x81010003 --out=private.pem
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
tpm2genkey --mode=tpm2pem --public=key.pub --private=key.prv --out=private.pem
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
tpm2genkey --mode=tpm2pem --public=key.pub --private=key.prv --parent=0x81010003 --out=private.pem 
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
tpm2genkey --mode=tpm2pem  --public=key.pub --private=key.prv --out=private.pem
# or with openssl1.1 (since openssl3 does not support this conversion):  
# tpm2tss-genkey -u key.pub -r key.prv private.pem

# now convert private.pem to key2.pub, key2.prv
tpm2genkey --mode=pem2tpm  --in=private.pem --public=key2.pub --private=key2.prv

### you may want to also print the key details using openssl which can give a hint about the
### primary (eg, if its a permanent handle, then probably regenerate  the 
###  h2 template itself i you don't have the primary.ctx handy
openssl asn1parse -inform PEM -in private.pem

## verify conversion by loading key2, you should see the same "name"
tpm2_load -C primary.ctx -u key2.pub -r key2.prv -c key2.ctx
```

### Appendix

#### Python (tpm2_pytss.TSSPrivKey)

Python tss also provides a way to create keys.  See

[https://tpm2-pytss.readthedocs.io/en/latest/_modules/tpm2_pytss/tsskey.html#TSSPrivKey](https://tpm2-pytss.readthedocs.io/en/latest/_modules/tpm2_pytss/tsskey.html#TSSPrivKey)


If you want to load keys generated by this tool into pytss, first create two keys (one with passphrase)
```bash
go run cmd/main.go --out=/tmp/private1.pem --tpm-path="127.0.0.1:2321"
go run cmd/main.go --out=/tmp/private2.pem --tpm-path="127.0.0.1:2321" --password=foo
```
then see see `python/load.py`


If you want to generate a key using pytss and then load load/convert them, see `python/create.py`

```bash
### create two rsa keys (one with password) and write them to /tmp/private1.pem and /tmp/private2.pem
#### note the "names"
# $  apt-get install libtss2-dev
$ python3 create.py 
  000be2d3e58350c6fa46cd52db2856f739c9d9457f3949301c99993cd6bed1b5ef96
  000b0a42610e5ec573a45f726e394cdee678356b6b3756194e3f3035a2e58830e5af

## create H2 Template
 printf '\x00\x00' > /tmp/unique.dat
 tpm2_createprimary -C o -G ecc  -g sha256 \
     -c primary.ctx \
     -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u /tmp/unique.dat

## export the pub/private parts to key tpm2_tools can read
go run cmd/main.go --in=/tmp/private1.pem --public=/tmp/key1.pub --private=/tmp/key1.prv
go run cmd/main.go --ownerpw=foo --in=/tmp/private2.pem --public=/tmp/key2.pub --private=/tmp/key2.prv

## load them 
tpm2_load -C primary.ctx -u key1.pub -r key1.prv -c key1.ctx
 name: 000be2d3e58350c6fa46cd52db2856f739c9d9457f3949301c99993cd6bed1b5ef96

tpm2_load -C primary.ctx -u key2.pub -r key2.prv -c key2.ctx 
 name: 000b0a42610e5ec573a45f726e394cdee678356b6b3756194e3f3035a2e58830e5af

## sign with the key that needs userauth
echo "my message" > message.dat
tpm2_sign -c key2.ctx -g sha256 -o sig.rssa message.dat -p foo
```

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
sudo swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert
sudo swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=5

## for tpm2_tools
export TPM2TOOLS_TCTI="swtpm:port=2321"
tpm2_pcrread sha256:23

## for openssl30
export TPM2OPENSSL_TCTI="swtpm:port=2321"

## then use this cli, set --tpm-path="127.0.0.1:2321"
tpm2genkey --mode=create --alg=rsa --out=private.pem --tpm-path="127.0.0.1:2321"
```

#### go-tpm

You can read the generated PEM files file using go-tpm as shown in the `example/` folder

```bash
## no passphrase:
go run cmd/main.go --mode=create --alg=rsa --out=/tmp/private.pem --tpm-path="127.0.0.1:2321"
go run main.go --keyfile=/tmp/private.pem --tpm-path="127.0.0.1:2321"
```

#### PEM Keyfile format

The TPM based keys are in PEM format compatible with openssl details of which you can find at [ASN.1 Specification for TPM 2.0 Key Files](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html).

You can generate or convert TPM based keys on your own using openssl, [tpm2tss-genkey](https://github.com/tpm2-software/tpm2-tss-engine/blob/master/man/tpm2tss-genkey.1.md) or [tpm2genkey](https://github.com/salrashid123/tpm2genkey)

decoded keys on TPM are readable as:

```bash
export OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules/
export TPM2OPENSSL_TCTI="swtpm:port=2321"

$ openssl rsa -provider tpm2  -provider default -in private.pem -text

Private-Key: (RSA 2048 bit, TPM 2.0)
Modulus:
    00:ec:26:5b:93:c6:09:b9:11:60:aa:d6:8f:21:6c:
    b5:6e:8a:52:30:b6:83:a1:0c:58:e7:61:ae:75:22:
    0d:8a:c9:da:dc:98:d0:32:20:a3:05:17:f4:c1:5d:
    06:f7:d7:05:09:81:e0:13:26:d7:be:74:53:4f:e0:
    e1:35:79:6e:bc:72:07:23:61:41:69:63:18:16:f4:
    27:8d:1c:33:31:59:61:6c:c1:76:f0:2c:e5:7c:e9:
    d4:d0:93:2b:07:27:77:10:2f:ab:c1:01:78:1c:27:
    68:e7:28:ba:ef:64:84:fe:62:2f:d4:f1:a8:ca:83:
    df:27:51:50:a3:b8:51:78:0b:04:be:d5:b5:43:a1:
    4c:89:fa:78:22:d6:45:50:f2:4a:1a:28:00:a5:6a:
    15:84:1b:46:51:de:2d:3c:65:c2:8b:9c:93:1d:53:
    da:4f:34:34:1f:b5:d3:d4:a7:81:aa:2b:44:80:b4:
    ff:58:51:2c:e7:cb:d4:53:18:ad:a3:49:81:9b:51:
    c5:4a:5d:f0:a7:7d:f7:eb:cc:00:89:13:9f:36:9e:
    8f:4d:23:7e:f2:36:dd:cb:cc:e3:b6:7b:b1:b9:4d:
    87:12:8a:33:2d:96:8c:c1:0a:6e:98:a3:54:29:98:
    86:79:97:33:42:6d:ca:e1:61:7b:bc:20:0d:30:54:
    92:3f
Exponent: 65537 (0x10001)
Object Attributes:
  userWithAuth
  sign / encrypt
Signature Scheme: PKCS1
  Hash: SHA256
writing RSA key
-----BEGIN TSS2 PRIVATE KEY-----
MIICNQYGZ4EFCgEDoAMBAQECBEAAAAEEggEaARgAAQALAAQAQAAAABAAFAALCAAA
AQABAQDsJluTxgm5EWCq1o8hbLVuilIwtoOhDFjnYa51Ig2KydrcmNAyIKMFF/TB
XQb31wUJgeATJte+dFNP4OE1eW68cgcjYUFpYxgW9CeNHDMxWWFswXbwLOV86dTQ
kysHJ3cQL6vBAXgcJ2jnKLrvZIT+Yi/U8ajKg98nUVCjuFF4CwS+1bVDoUyJ+ngi
1kVQ8koaKAClahWEG0ZR3i08ZcKLnJMdU9pPNDQftdPUp4GqK0SAtP9YUSzny9RT
GK2jSYGbUcVKXfCnfffrzACJE582no9NI37yNt3LzOO2e7G5TYcSijMtlozBCm6Y
o1QpmIZ5lzNCbcrhYXu8IA0wVJI/BIIBAAD+ACDBg/cpGTl++OOHhFwz+nBvPvNm
qdSNg+gqEzF1Eu2gNgAQ1qv0VDvcnIwo0DlItYWKfL7i1QHVMjp85eVgOGC8Qc65
VollWVse/DhTZOXz8N6qJhvXbj9HuRK2wdxka4mVjbAbgqNQdJfWbpyJk0d52hJ7
d71zvOwild71OLe/lvBqQlV3Hrk6Zvaed4C/38K3yPmICFR6YOfsFeDIAirzT+wp
9WGF9fq9CNzlKZgXAMoYLA6ZthtHKWdUUUYyyK0+yCqeNb32E5jN3Mn3GVxX9tc5
m5OgWpXX8bLqlRLY38P5J3HZOStjYxNBj5I3PdkvD7DFdlb7ZrJZoUg=
-----END TSS2 PRIVATE KEY-----
```

The `--enablePolicySyntax` flag enables optional unsupported syntax described [here](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html#name-key-policy-specification) but not officially adopted (see [tpm2-openssl/issues/120](https://github.com/tpm2-software/tpm2-openssl/issues/120)).

Specifically, if you enable the flag, the password and policy get encoded as a policy structure.  In the example below, `017F` is the PCRPolicy and the hex value is the command parameters; the `016B` is PolicyAuthValue.  However, openssl3 does not support these fields yet.

```bash
$ go run cmd/main.go --mode=create --alg=rsa --out=private.pem --password=foo --pcrs=23 --enablePolicySyntax  --tpm-path="127.0.0.1:2321"

$ openssl asn1parse -inform PEM -in private.pem
    0:d=0  hl=4 l= 631 cons: SEQUENCE          
    4:d=1  hl=2 l=   6 prim: OBJECT            :2.23.133.10.1.3
   12:d=1  hl=2 l=  70 cons: cont [ 1 ]        
   14:d=2  hl=2 l=  68 cons: SEQUENCE          
   16:d=3  hl=2 l=  54 cons: SEQUENCE          
   18:d=4  hl=2 l=   4 cons: cont [ 0 ]        
   20:d=5  hl=2 l=   2 prim: INTEGER           :017F
   24:d=4  hl=2 l=  46 cons: cont [ 1 ]        
   26:d=5  hl=2 l=  44 prim: OCTET STRING      [HEX DUMP]:0020E2F61C3F71D1DEFD3FA999DFA36953755C690689799962B48BEBD836974E8CF900000001000B03000080
   72:d=3  hl=2 l=  10 cons: SEQUENCE          
   74:d=4  hl=2 l=   4 cons: cont [ 0 ]        
   76:d=5  hl=2 l=   2 prim: INTEGER           :016B
   80:d=4  hl=2 l=   2 cons: cont [ 1 ]        
   82:d=5  hl=2 l=   0 prim: OCTET STRING      
   84:d=1  hl=2 l=   4 prim: INTEGER           :40000001
   90:d=1  hl=4 l= 314 prim: OCTET STRING      [HEX DUMP]:01380001000B00040072002034E22A9DA4D5CE704150EFFD67FB6994D5CFA1A6E2A04AA4514093F0F4D319D000100014000B0800000100010100B5CBC3568DE3D6245241EE436D4E9D2722D066488929610AE3BE558247D9F600F90D5CAA295B808FF5C61FA09524ED0A6EECB7044A3D620995510D1397050CF876D8E16591DC3D28A0416B1DEE7F4FFAC8A4CEDE200FEB82AB2CDC7976EF77D7E1ABFC8914B46719B8913B334D46F1A3301437C7C45A5C0570B682613220A9220598E0C06CBDE9BEAFBB5C2B240878B70727E39D753FE87F38A1E78856D8D094CE4FED4B57222F4596CFE1ADB70E15EE3B335AF8BB90A53ED5E55A8B5CBD368896154583437037F8CDA9AB180E7879C2A116303826F4CEA3DBA24A62FD23AB601C4FE7FCBA9392D3B9F26378EEDE77C8BC4B46E2782C9B5091101C79174E9993
  408:d=1  hl=3 l= 224 prim: OCTET STRING      [HEX DUMP]:00DE0020B4AC771D49800F4C6FB3450B118451A8EC1D47AA9D431B6AE1478B92D28D6AF900100AD2BA925F88B24485A05B4D6760B18E8E9E736DC1C6F9FA5A329839DC9FF3468C27DDBCEA358E7B0A1D8B7C28FBFFBBC968B7C94CA22B3A7EBF3FBFC2EDF8A285626DE449EA2517639F3ED238FAE0F459179F32E7F7D8C6E84CD4C462286D62AAE4ACFFED8702E580723FEF0056755FC17F94B0385B909736A313A6FA4CB267FB32FFB87CE21BC697DB5A40FA698A59D50BACF4BA3877F1159842E48579FC9D58BE12ED0B0B463D33FCEF08D37E541F541547800617C2812B35
```

Note, you can also convert a regular TPM pub/private key to PEM with a command policy if you specify `--commandCodePolicy` for the `tpm2pem` command

In the following, you're adding in a Policy to the PEM file manually (you need to have the command parameters handy as shown above)

```bash
## create H2 Template
printf '\x00\x00' > /tmp/unique.dat
tpm2_createprimary -C o -G ecc  -g sha256 \
     -c primary.ctx \
     -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u /tmp/unique.dat

tpm2_startauthsession --policy-session -S session.dat
tpm2_pcrread sha256:23 -o pcr23_val.bin
tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat -f pcr23_val.bin
tpm2_policyauthvalue -S session.dat -L policy.dat
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l  

tpm2_create -G rsa2048:rsassa:null -g sha256  -u key.pub -r key.prv  -C primary.ctx -L policy.dat -p foo
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l  
tpm2_load -C primary.ctx -u key.pub -r key.prv -n key.name -c key.ctx
    
# PolicyPCR 017F->383  
# PolicyAuthValue 016B->363
go run cmd/main.go --mode=tpm2pem --public=key.pub --private=key.prv \
    --commandCodePolicy=383:0020e2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf900000001000b03000080,363: \
    --out=private.pem 

openssl asn1parse -inform PEM -in private.pem
```