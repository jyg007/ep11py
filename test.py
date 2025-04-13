# main.py
from ep11constants import *
from pyep11 import Mechanism,Attribute, HsmInit, GenerateRandom,GenerateKey,GenerateKeyPair,OIDNamedCurveSecp256k1, SignSingle, VerifySingle,Reencipher, EncryptSingle,DecryptSingle,ReencryptSingle,GetMechanismList
from pyasn1.codec.der.encoder import encode



def main():
    target = HsmInit("3.19",True)

    mechanisms, error = GetMechanismList(target)

    if error:
        print(f"Error: {error}")
    else:
        print(f"Mechanisms: {mechanisms}")


    params = None
    mech = Mechanism(CKM_AES_KEY_GEN,params)
    keyTemplate = [
      Attribute(CKA_VALUE_LEN, 32),
      Attribute(CKA_UNWRAP, False),
      Attribute(CKA_ENCRYPT, True),
   ]

    # Call the GenerateKey function
    length = 32
    random_data = GenerateRandom(target, length)
    print(random_data.hex())
    # Assuming GenerateKey returns a tuple (key, error)


    aeskey, error = GenerateKey(target, mech, keyTemplate)

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
    aeskey2, error = GenerateKey(target, mech, keyTemplate)
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

if __name__ == "__main__":
    main()
