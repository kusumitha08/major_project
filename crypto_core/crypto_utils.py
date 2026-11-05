import hashlib
import json
import os
from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError

# ─────────────────────────────────────────
# File to store registered citizens
# ─────────────────────────────────────────
DATA_FILE = "citizens.json"

# ─────────────────────────────────────────
# STEP 1: SHA-256 Identity Hashing
# ─────────────────────────────────────────
def generate_identity_hash(name, dob, aadhaar_id):
    raw_data = name + dob + aadhaar_id
    return hashlib.sha256(raw_data.encode()).hexdigest()

def generate_name_hash(name):
    return hashlib.sha256(name.strip().casefold().encode()).hexdigest()

# ─────────────────────────────────────────
# STEP 2: Generate ECDSA Key Pair
# ─────────────────────────────────────────
def generate_keys():
    private_key = SigningKey.generate(curve=SECP256k1)
    public_key  = private_key.get_verifying_key()
    return private_key, public_key

# ─────────────────────────────────────────
# STEP 3: Sign Identity Hash
# ─────────────────────────────────────────
def sign_identity(private_key, identity_hash):
    signature = private_key.sign(identity_hash.encode())
    return signature.hex()

# ─────────────────────────────────────────
# STEP 4: Verify Signature
# ─────────────────────────────────────────
def verify_signature(public_key, identity_hash, signature_hex):
    try:
        signature = bytes.fromhex(signature_hex)
        public_key.verify(signature, identity_hash.encode())
        return True
    except (BadSignatureError, ValueError):
        return False


def sign_verification_message(private_key, identity_hash, nonce, request_id):
    try:
        from middleware.replay_protection import hash_verification_message
    except ImportError:
        from replay_protection import hash_verification_message

    message_hash = hash_verification_message(identity_hash, nonce, request_id)
    return private_key.sign(message_hash.encode("utf-8")).hex()


def verify_verification_signature(public_key, identity_hash, nonce, request_id, signature_hex):
    try:
        from middleware.replay_protection import hash_verification_message
    except ImportError:
        from replay_protection import hash_verification_message

    try:
        signature = bytes.fromhex(signature_hex)
        message_hash = hash_verification_message(identity_hash, nonce, request_id)
        public_key.verify(signature, message_hash.encode("utf-8"))
        return True
    except (BadSignatureError, ValueError):
        return False

# ─────────────────────────────────────────
# STEP 5: Load existing citizens from file
# ─────────────────────────────────────────
def load_citizens():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

# ─────────────────────────────────────────
# STEP 6: Save citizens to file
# ─────────────────────────────────────────
def save_citizens(citizens):
    with open(DATA_FILE, "w") as f:
        json.dump(citizens, f, indent=4)
    print(f"   Data saved to {DATA_FILE} ✅")

# ─────────────────────────────────────────
# STEP 7: Register a new citizen
# ─────────────────────────────────────────
def register_citizen(name, dob, aadhaar_id, private_key):
    citizens = load_citizens()

    # Check if Aadhaar ID already registered
    if aadhaar_id in citizens:
        print(f"   ⚠️  Aadhaar ID {aadhaar_id} already registered!")
        return None

    # Generate hash and signature
    identity_hash = generate_identity_hash(name, dob, aadhaar_id)
    signature     = sign_identity(private_key, identity_hash)

    # Store citizen record
    citizens[aadhaar_id] = {
        "name"          : name,
        "dob"           : dob,
        "aadhaar_id"    : aadhaar_id,
        "identity_hash" : identity_hash,
        "signature"     : signature
    }

    save_citizens(citizens)
    return identity_hash, signature

# ─────────────────────────────────────────
# STEP 8: Display all registered citizens
# ─────────────────────────────────────────
def display_all_citizens():
    citizens = load_citizens()
    if not citizens:
        print("   No citizens registered yet.")
        return
    print(f"\n   Total registered citizens: {len(citizens)}")
    print("   " + "-" * 55)
    for aadhaar_id, data in citizens.items():
        print(f"   👤 {data['name']} | DOB: {data['dob']} | Aadhaar: {aadhaar_id}")
        print(f"      Hash: {data['identity_hash'][:30]}...")
    print("   " + "-" * 55)

# ─────────────────────────────────────────
# MAIN MENU
# ─────────────────────────────────────────
if __name__ == "__main__":

    # One master key pair for Aadhaar authority
    # In real use, this would be loaded from a secure file
    private_key, public_key = generate_keys()
    print("\n✅ Aadhaar Authority Keys Generated\n")

    while True:
        print("\n========= AADHAAR IDENTITY SYSTEM =========")
        print("  1. Register new citizen")
        print("  2. Verify existing citizen")
        print("  3. View all registered citizens")
        print("  4. Exit")
        print("============================================")
        choice = input("Enter choice (1/2/3/4): ").strip()

        # ── REGISTER ──
        if choice == "1":
            print("\n--- Register New Citizen ---")
            name        = input("Enter Full Name    : ").strip()
            dob         = input("Enter DOB (DD-MM-YYYY): ").strip()
            aadhaar_id  = input("Enter Aadhaar ID   : ").strip()

            print()
            result = register_citizen(name, dob, aadhaar_id, private_key)
            if result:
                identity_hash, signature = result
                print(f"   👤 Name      : {name}")
                print(f"   Hash        : {identity_hash[:30]}...")
                print(f"   Signature   : {signature[:30]}...")
                print(f"   ✅ Citizen registered successfully!")

        # ── VERIFY ──
        elif choice == "2":
            print("\n--- Verify Citizen ---")
            aadhaar_id = input("Enter Aadhaar ID to verify: ").strip()
            citizens   = load_citizens()

            if aadhaar_id not in citizens:
                print("   ❌ Aadhaar ID not found in system!")
            else:
                data          = citizens[aadhaar_id]
                identity_hash = data["identity_hash"]
                signature     = data["signature"]
                result        = verify_signature(public_key, identity_hash, signature)

                print(f"\n   👤 Name      : {data['name']}")
                print(f"   DOB         : {data['dob']}")
                print(f"   Hash        : {identity_hash[:30]}...")
                print(f"   Verification: {'✅ Valid — Identity Confirmed!' if result else '❌ Invalid — Tampered Data!'}")

        # ── VIEW ALL ──
        elif choice == "3":
            display_all_citizens()

        # ── EXIT ──
        elif choice == "4":
            print("\n👋 Exiting system. Goodbye!\n")
            break

        else:
            print("   ⚠️  Invalid choice. Please enter 1, 2, 3 or 4.")