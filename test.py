# main.py
from ep11constants import *
from pyep11 import Mechanism,Attribute, HsmInit, GenerateRandom,GenerateKey,GenerateKeyPair,OIDNamedCurveSecp256k1, SignSingle, VerifySingle,Reencipher, EncryptSingle,DecryptSingle,ReencryptSingle,GetMechanismList,WrapKey,UnwrapKey,DeriveKey, NewBTCDeriveParams
from pyasn1.codec.der.encoder import encode

import binascii,os
from pyasn1.codec.der.encoder import encode as asn1_encode

def slip10_deriveKey(
    target: int,
    derive_type: int ,
    child_key_index: int,
    hardened: bool,
    base_key: bytes,
    chain_code: bytes ,
):
    # --- Hardened derivation ---
    if hardened:
        child_key_index += CK_IBM_BTC_BIP0032_HARDENED

    # --- EC parameters (secp256k1) ---
    ecParameters = encode(OIDNamedCurveSecp256k1)

    # --- Derive key template ---
    DeriveKeyTemplate = {
        Attribute(CKA_EC_PARAMS, ecParameters),
        Attribute(CKA_SIGN, True),
        Attribute(CKA_PRIVATE, True),
        Attribute(CKA_SENSITIVE, True),
        Attribute(CKA_VERIFY, True),
        Attribute(CKA_DERIVE, True),
        Attribute(CKA_KEY_TYPE,CKK_ECDSA),
        Attribute(CKA_VALUE_LEN,0),
        Attribute(CKA_IBM_USE_AS_DATA, True)
    }

    # --- Derive key ---
    try:
        mech = Mechanism( CKM_IBM_BTC_DERIVE, NewBTCDeriveParams( derive_type,child_key_index , chain_code, XCP_BTC_VERSION))

        new_key_bytes, checksum = DeriveKey(
            target,
            mech,
            base_key,
            DeriveKeyTemplate,
        )
    except Exception as e:
        raise RuntimeError(f"Derived Child Key request error: {e}") from e

    return new_key_bytes, checksum


def main():
    target = HsmInit("3.19")

    mechanisms, error = GetMechanismList(target)

    if error:
        print(f"Error: {error}")
    else:
        print(f"Mechanisms: {mechanisms}")


    params = None
    mech = Mechanism(CKM_AES_KEY_GEN,params)
    keyTemplate = [
      Attribute(CKA_VALUE_LEN, 32),
      Attribute(CKA_UNWRAP, True),
      Attribute(CKA_WRAP, True),
      Attribute(CKA_ENCRYPT, True),
   ]

    # Call the GenerateKey function
    length = 32
    random_data = GenerateRandom(target, length)
    print(random_data.hex())
    # Assuming GenerateKey returns a tuple (key, error)


    aeskey, csum, error = GenerateKey(target, mech, keyTemplate)

    # Check if there was an error
    if error:
       print(f"Error: {error}")
    else:
       # Print the hexadecimal string representation of the key
       print(f"Generated key: {aeskey.hex()}")

      # Call Reencipher
    new_key_blob, error = Reencipher(target, aeskey)
    if error:
        print("Reencipher failed:", error)
    else:
        print("Reenciphered key blob:", new_key_blob.hex())

    iv_str = "abcedefghij"
    iv = iv_str.encode("utf-8").ljust(16, b'\x00')
    mech = Mechanism(CKM_AES_CBC_PAD, iv)
    # Call the encryption function
    cipher, err = EncryptSingle(target, mech, aeskey,b"Hello World!")

    if err:
        print(f"Encryption failed: {err}")
        return

    print("\nCipher:\n" + cipher.hex()) 

    plain, error = DecryptSingle(target, mech, aeskey, cipher)
    if error:
        print(f"Decryption failed: {error}")
    else:
        print(f"Plaintext: {plain.decode('utf-8', errors='ignore')}")

    mech = Mechanism(CKM_AES_KEY_GEN,None)
    aeskey2, csum,error = GenerateKey(target, mech, keyTemplate)
    if error:
       print(f"Error: {error}")
    else:
       print(f"Generated key: {aeskey.hex()}")

    mech = Mechanism(CKM_AES_CBC_PAD, iv)
    iv2_str = "abcedefghij"
    iv2 = iv2_str.encode("utf-8").ljust(16, b'\x00')
    mech2 = Mechanism(CKM_AES_CBC_PAD, iv2)
    recipher, error = ReencryptSingle(target, mech, mech2,  aeskey ,aeskey2 ,cipher)
    
    if error:
        print(f"Reencryption failed: {error}")
    else:
        print("\nReCipher:\n" + recipher.hex()) 
    plain, error = DecryptSingle(target, mech2, aeskey2, recipher)
    if error:
        print(f"Decryption failed: {error}")
    else:
        print(f"Plaintext: {plain.decode('utf-8', errors='ignore')}")

    print("\n")
    ecParameters = encode(OIDNamedCurveSecp256k1)
    
    mech = Mechanism(CKM_EC_KEY_PAIR_GEN,None)
    publicKeyECTemplate = [
            Attribute(CKA_EC_PARAMS, ecParameters),
            Attribute(CKA_VERIFY, True),
    ]
    print(publicKeyECTemplate)
    privateKeyECTemplate = [
            Attribute(CKA_EC_PARAMS, ecParameters),
            Attribute(CKA_SIGN, True),
            Attribute(CKA_PRIVATE, True),
            Attribute(CKA_SENSITIVE, True),
    ]
    pk,sk, error = GenerateKeyPair(target, mech, publicKeyECTemplate,privateKeyECTemplate)
    # Check if there was an error
    if error:
       print(f"Error: {error}")
    else:
       # Print the hexadecimal string representation of the key
       print(f"Generated Private key: {sk.hex()}")
       print(f"Generated Public key: {pk.hex()}")


    mech = Mechanism(CKM_ECDSA,None)
    sig , error = SignSingle(target, mech, sk, b"hello world!")
    if error:
       print(f"Error: {error}")
    else:
       # Print the hexadecimal string representation of the key
       print(f"Signature: {sig.hex()}")

    error = VerifySingle(target, mech, pk, b"hello world!", sig)
    if error:
      print(f"Verification failed: {error}")
    else:
      print("Signature is valid!")

    error = VerifySingle(target, mech, pk, b"Hello world!", sig)
    if error:
      print(f"Verification failed: {error}")
    else:
      print("Signature is valid!")

    mech = Mechanism(CKM_AES_CBC_PAD, iv)
    wrappedkey, error = WrapKey(target,  mech, aeskey, aeskey2)
    if error:
       print(f"Error: {error}")
    else:
       print(f"Generated wrapped key: {wrappedkey.hex()}")

    keyTemplate = [
      Attribute(CKA_KEY_TYPE, CKK_AES),
      Attribute(CKA_VALUE_LEN, 32),
      Attribute(CKA_UNWRAP, True),
      Attribute(CKA_WRAP, True),
      Attribute(CKA_ENCRYPT, True),
    ]
    unwrappedkey, csum, error = UnwrapKey(target,  mech, aeskey, wrappedkey,keyTemplate)
    if error:
       print(f"Error: {error}")
    else:
       print(f"Generated unwrapped key: {unwrappedkey.hex()}")

    # --- Decode MASTERSEED from hex ---
    masterseed_hex = os.environ.get("MASTERSEED")
    if not masterseed_hex:
        raise RuntimeError("MASTERSEED environment variable not set")

    seed = binascii.unhexlify(masterseed_hex)

    # --- Path split ---
    #path = sys.argv[1].encode().split(b"/")

    # --- SLIP-10 master derivation ---
    sk, chaincode = slip10_deriveKey( target, CK_IBM_BTC_SLIP0010_MASTERK, 0, False, seed, None)
    print(f"Generated derived key: {sk.hex()}")
    print(f"Generated derived chaincode: {chaincode.hex()}")
    childsk, childchaincode = slip10_deriveKey( target, CK_IBM_BTC_SLIP0010_PRV2PRV, 1, True, sk, chaincode)
    print(f"Generated derived childkey: {childsk.hex()}")
    print(f"Generated derived childchaincode: {childchaincode.hex()}")
    childpub, childpubchaincode = slip10_deriveKey( target, CK_IBM_BTC_SLIP0010_PRV2PUB, 1, True, sk, chaincode)
    print(f"Generated derived childpubkey: {childpub.hex()}")
    print(f"Generated derived childpubchaincode: {childpubchaincode.hex()}")
    

if __name__ == "__main__":
    main()
