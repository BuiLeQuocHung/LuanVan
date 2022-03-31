import binascii, ed25519, hashlib, base58, ecdsa
from hdwallet import HDWallet
from hdwallet.utils import generate_entropy
from hdwallet.symbols import BTC as SYMBOL
from DatabaseConnect.connect_database import *
from Structure.Block import *

path_dir = {
    "lvcoin": "m'/44'/0'/0'/0/0"
}

def pubkey_to_address(pubkey: str):
    hash1 = hashlib.sha256(pubkey.encode()).hexdigest()
    hash2 = hashlib.new('ripemd160', hash1.encode()).hexdigest()

    hash3 = hashlib.sha256(hash2.encode()).hexdigest()
    hash4 = hashlib.sha256(hash3.encode()).hexdigest()

    #first 4 bytes of hash4
    checksum = hash4[:8]

    result = hash2 + checksum

    return base58.b58encode(binascii.unhexlify(result)).decode()

def create_hdwallet_from_entropy(entropy):
    STRENGTH: int = 128  # Default is 128
    LANGUAGE: str = "english"  # Default is english
    ENTROPY: str = generate_entropy(strength=STRENGTH)
    PASSPHRASE: str = None  # "meherett"

    hd_wallet: HDWallet = HDWallet(symbol=SYMBOL, use_default_path=False)
    hd_wallet.from_entropy(
        entropy=ENTROPY, language=LANGUAGE, passphrase=PASSPHRASE
    )

    return hd_wallet


def create_address_ed25519(hdwallet: HDWallet):
    hdwallet.from_path(path_dir['lvcoin'])
    privkey = hdwallet.private_key()
    hdwallet.clean_derivation()

    privkey_ed25519 = ed25519.SigningKey(binascii.unhexlify(privkey.encode()))
    pubkey_ed25519 = privkey_ed25519.get_verifying_key()
    address_ed25519 = pubkey_to_address(pubkey_ed25519.to_bytes().decode())

    return address_ed25519

def add_address_to_firebase(address_ed25519, userID):
    ref = db.reference("/address/lvcoin")
    ref.set({
        address_ed25519: userID
    })

def add_new_address(entropy, userID):
    hdwallet = create_hdwallet_from_entropy(entropy)
    address_ed25519 = create_address_ed25519(hdwallet)
    add_address_to_firebase(address_ed25519, userID)

def check_money_send_to_platform(block: Block):
    ref = db.reference("/address/lvcoin")
    addresses = ref.get()
    
    for trans in block.BlockBody.transList:
        for output in trans.outputList:
            if output.recvAddress in addresses:
                userID = addresses[output.recvAddress]
                update_balance(output.amount, userID)

def update_balance(amount, userID):
    ref = db.reference("/user/{}/own".format(userID))
    owned = ref.get()
    new_lvcoin_balance = int(owned['lvcoin']) + amount

    ref.update({
        'lvcoin': new_lvcoin_balance
    })





