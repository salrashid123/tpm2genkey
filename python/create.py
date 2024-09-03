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

k1 = TSSPrivKey.create_rsa(ectx)
lk1 = k1.load(ectx=ectx,password='')
print(lk1.get_name(ectx))


with open("/tmp/private1.pem", "wb") as f:
    f.write(k1.to_pem())

ectx.flush_context(lk1)


k2 = TSSPrivKey.create_rsa(ectx, password="foo")
lk2 = k2.load(ectx=ectx,password="foo")
print(lk2.get_name(ectx))
with open("/tmp/private2.pem", "wb") as f:
    f.write(k2.to_pem())
ectx.flush_context(lk2)

ectx.close()
