# main.py
from ep11constants import *
from pyep11 import Mechanism,Attribute, HsmInit, UnwrapKey, NewOAEPParams
from pyasn1.codec.der.encoder import encode
import binascii
import sys

def main():
    target = HsmInit("3.19",True)

    keyTemplate = [
      Attribute(CKA_KEY_TYPE, CKK_AES),
      Attribute(CKA_CLASS, CKO_SECRET_KEY),
      Attribute(CKA_VALUE_LEN, 32),
      Attribute(CKA_UNWRAP, False ),
      Attribute(CKA_WRAP, False),
      Attribute(CKA_DERIVE, True),
      Attribute(CKA_IBM_USE_AS_DATA, True),
    ]

    sk  = binascii.unhexlify(sys.argv[1])
    wrappedkey = binascii.unhexlify(sys.argv[2])

    iv = bytes(16)
    mech= Mechanism(CKM_AES_CBC , iv) 

    unwrappedkey, csum, error = UnwrapKey(target,  mech, sk, wrappedkey,keyTemplate)

    if error:
       print(f"Error: {error}")
    else:
       print(f"unwrapped transport key: {unwrappedkey.hex()}")
       print(f"checksum: {csum.hex()}")

if __name__ == "__main__":
    main()
