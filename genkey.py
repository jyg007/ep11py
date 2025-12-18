from pkcs11 import KeyType, Attribute, Mechanism
import pkcs11

# Path to the opencryptoki pkcs11 library (usually this for IBM Z/LinuxONE)
# You may need to adjust depending on your distro/setup
PKCS11_LIB = "/usr/lib64/opencryptoki/libopencryptoki.so"

# Load PKCS#11 library
lib = pkcs11.lib(PKCS11_LIB)

# Open a session on the desired slot (slot 0 here, adapt as needed)
token = lib.get_token(token_label='jygfips')
# Login with SO/USER PIN
with token.open(user_pin='87654321', rw=True) as session:

    # EC Parameters for secp256k1 (OID: 1.3.132.0.10)
    secp256k1_oid = bytes.fromhex("06052B8104000A")

    # Generate keypair
    pub, priv = session.generate_keypair(
        KeyType.EC, 
        key_length=256,
        mechanism=Mechanism.EC_KEY_PAIR_GEN,
        store=True,   # store on token
        public_template={
            Attribute.EC_PARAMS: secp256k1_oid,
            Attribute.LABEL: "secp256k1-public",
            Attribute.VERIFY: True,
        },
        private_template={
            Attribute.LABEL: "secp256k1-private",
            Attribute.SIGN: True,
            Attribute.SENSITIVE: True,
            Attribute.EXTRACTABLE: False,
        }
    )

    print("Generated secp256k1 key pair in HSM:")
    print("  Public Key Handle:", pub)
    print("  Private Key Handle:", priv)
