# main.py
from ep11constants import *
from pyep11 import Mechanism,Attribute, HsmInit, UnwrapKey, NewOAEPParams
from pyasn1.codec.der.encoder import encode
import binascii
import sys

def main():
    target = HsmInit("3.19")

    keyTemplate = [
      Attribute(CKA_KEY_TYPE, CKK_AES),
      Attribute(CKA_CLASS, CKO_SECRET_KEY),
      Attribute(CKA_VALUE_LEN, 32),
      Attribute(CKA_UNWRAP, True),
      Attribute(CKA_WRAP, True),
      Attribute(CKA_ENCRYPT, True),
    ]

    rsask  = binascii.unhexlify(sys.argv[1])
    wrappedkey = binascii.unhexlify(sys.argv[2])

    mech= Mechanism(CKM_RSA_PKCS_OAEP,NewOAEPParams(CKM_SHA256, CKG_MGF1_SHA256,  0, "" )) 

    unwrappedkey, csum, error = UnwrapKey(target,  mech, rsask, wrappedkey,keyTemplate)

    if error:
       print(f"Error: {error}")
    else:
       print(f"unwrapped transport key: {unwrappedkey.hex()}")
       print(f"checksum: {csum.hex()}")

if __name__ == "__main__":
    main()
