from tpm2_pytss import *


from tpm2_pytss.tsskey import TSSPrivKey, _parent_rsa_template, _parent_ecc_template, _loadablekey_oid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def sha256(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    digest = digest.finalize()
    return digest


ectx = ESAPI(tcti="swtpm:port=2321")
#ectx.startup(TPM2_SU.CLEAR)

f = open('/tmp/private1.pem', 'r')
rsa_pem = f.read()
f.close()

k = TSSPrivKey.from_pem(rsa_pem.encode())
lk = k.load(ectx=ectx,password='')
print(lk.get_name(ectx))

digest = sha256(b"fff")
scheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.RSASSA)
scheme.details.any.hashAlg = TPM2_ALG.SHA256
validation = TPMT_TK_HASHCHECK(tag=TPM2_ST.HASHCHECK, hierarchy=TPM2_RH.OWNER)
digest, ticket = ectx.hash(b"fff", TPM2_ALG.SHA256, ESYS_TR.OWNER)
signature = ectx.sign(lk, TPM2B_DIGEST(digest), scheme, validation)
print(signature.marshal().hex())
ectx.verify_signature(lk,  TPM2B_DIGEST(digest), signature)

ectx.flush_context(lk)

# ***************

f = open('/tmp/private2.pem', 'r')
rsa_pem = f.read()
f.close()

kp = TSSPrivKey.from_pem(rsa_pem.encode())
lkp = kp.load(ectx=ectx,password='foo')

print(lkp.get_name(ectx))
ectx.flush_context(lkp)

ectx.close()
