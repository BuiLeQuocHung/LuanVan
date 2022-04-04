import binascii, ed25519, hashlib, base58, ecdsa, time
from hdwallet import HDWallet
from hdwallet.utils import generate_entropy
from hdwallet.symbols import BTC as SYMBOL
from DatabaseConnect.connect_database import *
from Structure.Block import *
from config import root_path


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
    print(ENTROPY)
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

def getBlockCluster(blockHeight):
    return blockHeight // 100

def getblock(blockHeight: int) -> Block: 
    blockDataPath =  os.path.join(root_path, 'BlockData')
    blockClusterPath = os.path.join(blockDataPath, 'Cluster') + str(getBlockCluster(blockHeight))

    if not os.path.exists(blockClusterPath):
        return None

    blockPath = blockClusterPath + '/' + '{}.txt'.format(blockHeight)
    if not os.path.exists(blockPath):
        return None
    
    with open(blockPath, 'rb') as file:
        # block_json = json.load(file)
        block = Block.from_binary(file.read())

    # return Block.from_json(block_json)
    return block

def get_addr_UTXO(collection_name: str, address: str):
    {
        '_id': 123,
        'amount': 123,
        'recvAddress': 123,
        'script_type': 123
    }
    # result = [] #list of dictionaries
    # cursor =  mydb[collection_name].find({"address" : address})
    # for record in cursor:
    #     result.append(record)
    # return result

    addr_UTXOs_index = mydb['UserAddress'].find_one({'_id': address})

    result = []
    if addr_UTXOs_index == None:
        return result
    
    for each in addr_UTXOs_index['list_UTXOs']:
        UTXO_id = each['UTXO_id']
        trans_hash = UTXO_id[:64]
        idx = int(UTXO_id[64:])
        blockHeight = each['blockHeight']

        block = getblock(blockHeight)
        # print(block.toJSON())
        for trans in block.BlockBody.transList:
            if trans.hash == trans_hash:
                output_json = trans.outputList[idx].toJSON()
                output_json['_id'] = UTXO_id
                result.append(output_json)
                break
    return result

def trans_to_mempool(trans: Transaction):
    trans_json = trans.toJSONwithSignature()
    trans_json['_id'] = trans.hash
    mydb['Mempool'].insert_one(trans_json)


def widthdrawn_money(amount, address):
    privKey_str = "3347abc7e2490f12b50e845668bd3f657252fbb698f5a205012a928fada44857"
    privKey = ed25519.SigningKey(binascii.unhexlify(privKey_str.encode()))
    pubKey = privKey.get_verifying_key()
    pubKey_str = pubKey.to_bytes().hex()
    platform_address = pubkey_to_address(pubKey_str)

    fee = 1
    inputList = []
    totalInputAmount = 0

    address_UTXOs_info = get_addr_UTXO(platform_address)
    for UTXO_info in address_UTXOs_info:
        txid, idx = UTXO_info['_id'][:64], int(UTXO_info['_id'][64:])
        inputAmount = UTXO_info['amount']

        newInput = TransactionInput(txid, idx, pubKey)
        inputList.append(newInput)

        totalInputAmount += inputAmount

        if totalInputAmount > amount + fee:
            break
    outputList =[TransactionOutput(amount, address)]

    change = totalInputAmount - amount - fee
    if change > 0:
        change_output = TransactionOutput(change, platform_address)
        outputList.append(change_output)

    trans = Transaction(inputList, outputList, time.time())
    trans_to_mempool(trans)


