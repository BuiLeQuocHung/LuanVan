import socket, os, json, ed25519, base58
from _thread import *

from config import *
from Structure.Block import *
from DatabaseConnect.connect_database import *
from bitcoin import *

from itertools import repeat
from functools import reduce
from multiprocessing import Pool
from bson import ObjectId
from update_balance_from_blockchain import check_money_send_to_platform


# def receiveAll(ClientSocket: socket.socket, n: int):
#     data = bytearray()
#     while len(data) < n:
#         packet = ClientSocket.recv(n - len(data))
#         # if not packet:
#         #     return None
#         data.extend(packet)
#     return data

def trans_to_mempool(trans: Transaction):
    trans_json = trans.toJSONwithSignature()
    trans_json['_id'] = trans.hash
    mydb['Mempool'].insert_one(trans_json)

def count_record(collection_name: str):
    return mydb[collection_name].count_documents({})

def get_blockchain_info():
    blockchain_info_path = os.path.join(root_path, 'BlockchainInfo')
    blockchaininfotxt_path = blockchain_info_path + '/{}.txt'.format('blockchaininfo')

    try:
        with open(blockchaininfotxt_path, "r+") as file:
            blockchain_info = json.load(file)
    except:
        return None

    return blockchain_info #dictionary

    # {
    #     height: int,
    #     bestBlockHash: str,
    #     difficulty: int
    # }

def update_blockchain_info(new_height, block_hash, targetDiff):
    blockchain_info = get_blockchain_info()

    if blockchain_info:
        blockchain_info['height'] = new_height
        blockchain_info['bestBlockHash'] = block_hash
        blockchain_info['difficulty'] = targetDiff
    else:
        blockchain_info = {
            'height': 0,
            'bestBlockHash': block_hash,
            'difficulty': targetDiff
        }

    blockchain_info_path = os.path.join(root_path, 'BlockchainInfo')
    blockchaininfotxt_path = blockchain_info_path + '/{}.txt'.format('blockchaininfo')

    with open(blockchaininfotxt_path, "w+") as file:
        json.dump(blockchain_info, file, sort_keys=True, indent= 4, separators=(', ', ': '))

def getBlockCluster(blockHeight):
    return blockHeight // 100

def get_UTXO_index_info_parallel(tran_hash: str, idx: int):
    a = ['Chainstate0', 'Chainstate1', 'Chainstate2', 'Chainstate3']

    result = None
    for x in p.starmap(get_UTXO_index_info, zip(a, repeat(tran_hash), repeat(idx))):
        if x != None:
            result = x
    
    
    return result

def get_UTXO_index_info(collection_name: str, tran_hash: str, idx: int):
    return mydb[collection_name].find_one({"_id": tran_hash + str(idx)})

def get_tran_index_info_parallel(tran_hash: str):
    a = ['Transaction0', 'Transaction1', 'Transaction2', 'Transaction3']

    for x in p.starmap(get_tran_index_info, zip(a, repeat(tran_hash))):
        if x != None:
            result = x
    
    
    return result

def get_tran_index_info(collection_name: str, tran_hash: str):
    return mydb[collection_name].find_one({"_id": tran_hash})

def get_block_index_info(block_hash: str):
    return mydb['Block'].find_one({"_id": block_hash})

def get_addr_UTXO_parallel(address: str):
    a = ['Chainstate0', 'Chainstate1', 'Chainstate2', 'Chainstate3']
    result =  list(reduce(lambda x,y : x + y,  p.starmap(get_addr_UTXO, zip(a, repeat(address))), []))
    return result

def get_addr_UTXO(collection_name: str, address: str):
    result = [] #list of dictionaries
    cursor =  mydb[collection_name].find({"address" : address})
    for record in cursor:
        result.append(record)
    return result

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

def getblockheader(blockHeight: int) -> BlockHeader:
    block = getblock(blockHeight)
    if block == None:
        return None
    return block.BlockHeader

def getlistblockheaders(start: int, end: int) -> BlockHeader:
    result = []
    for i in range(start, end + 1):
        temp = getblockheader(i)
        if temp != None:
            result.append(temp.toJSON())
    return result

def writeblock(block: Block, blockHeight: int):
    blockDataPath = os.path.join(root_path, "BlockData")
    blockClusterPath = os.path.join(blockDataPath, 'Cluster') + str(getBlockCluster(blockHeight))

    if not os.path.exists(blockClusterPath):
        os.makedirs(blockClusterPath)

    blockPath = blockClusterPath + '/' + '{}.txt'.format(blockHeight)

    #write block data
    with open(blockPath, 'wb+') as file:
        # json.dump(block.toJSON(), file, indent= 4, separators=(', ', ': '))
        file.write(block.to_binary())

    writeBlockIndex(block.hash, blockHeight)

    #update database
    transList = block.BlockBody.transList
    for tran_idx, tran in enumerate(transList):
        for input_idx, input in enumerate(tran.inputList):
            deleteUTXO_parallel(input.txid, input.idx)

        for output_idx, output in enumerate(tran.outputList):
            writeUTXO(output, tran.hash, output_idx, blockHeight)

        writeTrans(tran.hash, blockHeight, tran_idx)
    
def writeBlockIndex(block_hash, blockHeight):
    mydb['Block'].insert_one({"_id": block_hash, "blockHeight": blockHeight})

def deleteBlockIndex(block_hash):
    mydb['Block'].delete_one({"_id": block_hash})

def deleteBlock(blockHeight: int):
    blockDataPath = os.path.join(root_path, "BlockData")
    blockClusterPath = os.path.join(blockDataPath, 'Cluster') + str(getBlockCluster(blockHeight))
    blockPath = blockClusterPath + '/' + '{}.txt'.format(blockHeight)

    block = getblock(blockHeight)

    transList = block.BlockBody.transList
    for tran_idx, tran in enumerate(transList):
        for output_idx, output in enumerate(tran.outputList):
            deleteUTXO_parallel(tran.hash, output_idx)

        for input_idx, input in enumerate(tran.inputList):
            UTXOutput = getTransOutput(input.txid, input.idx)
            UTXO_blockHeight = get_tran_index_info_parallel(input.txid)['blockHeight']
            writeUTXO(UTXOutput, input.txid, input.idx, UTXO_blockHeight)

        deleteTrans_parallel(tran.hash)
    
    deleteBlockIndex(block.hash)

    os.remove(blockPath)


def getTrans(tran_hash: str):
    tran_index_info = get_tran_index_info_parallel(tran_hash)

    if not tran_index_info:
        return

    blockHeight = tran_index_info['blockHeight']
    block = getblock(blockHeight)

    idx = tran_index_info['idx']
    transaction = block.BlockBody.transList[idx]

    return transaction

def getTransOutput(trans_hash: str, idx: int) -> TransactionOutput:
    trans = getTrans(trans_hash)
    return trans.outputList[idx]

def deleteTrans_parallel(tran_hash):
    a = ['Transaction0', 'Transaction1', 'Transaction2', 'Transaction3']
    result = None
    for x in p.starmap(deleteTrans, zip(a, repeat(tran_hash))):
        if x != None:
            result = x
    
    
    return result

def deleteTrans(collection_name: str, tran_hash: str):
    return mydb[collection_name].delete_one({"_id": tran_hash})


def writeTrans(tran_hash: str, blockHeight: int, idx: int):
    a = ['Transaction0', 'Transaction1', 'Transaction2', 'Transaction3']

    result = p.map(count_record, a)
    smallest_records= min(result)
    collection_index = result.index(smallest_records)

    record = {
        "_id": tran_hash,
        "blockHeight": blockHeight,
        "idx": idx
    }
    
    mydb[a[collection_index]].insert_one(record)

def getUTXO(tran_hash: str, idx: int) -> TransactionOutput:
    UTXO_index_info = get_UTXO_index_info_parallel(tran_hash, idx)
    block = getblock(UTXO_index_info['blockHeight'])

    for trans in block.BlockBody.transList:
        if trans.hash == tran_hash:
            return trans.outputList[idx]

    return None

def deleteUTXO_parallel(tran_hash: str, idx: int):
    a = ['Chainstate0', 'Chainstate1', 'Chainstate2', 'Chainstate3']
    result = None
    for x in p.starmap(deleteUTXO, zip(a, repeat(tran_hash), repeat(idx))):
        if x != None:
            result = x
    
    return result

def deleteUTXO(collection_name: str, tran_hash: str, idx: int):
    return mydb[collection_name].delete_one({"_id": tran_hash + str(idx)})

def writeUTXO(UTXO: TransactionOutput, tran_hash: str, idx: int, blockHeight: int):
    a = ['Chainstate0', 'Chainstate1', 'Chainstate2', 'Chainstate3']

    result = p.map(count_record, a)
    smallest_records= min(result)
    collection_index = result.index(smallest_records)
    
    record = {
        "_id": tran_hash + str(idx),
        "blockHeight": blockHeight,
        # "address": UTXO.recvAddress,
        # "amount": UTXO.amount,
        # "script_type": UTXO.script_type
    }

    mydb[a[collection_index]].insert_one(record)

def verify_block(block: Block):
    if len(block.BlockBody.transList) == 0:
        print("here 1 block")
        return False

    checkCoinbase = False

    used_UTXOs = []

    for trans in block.BlockBody.transList:
        if len(trans.inputList) == 0:
            if not checkCoinbase:
                checkCoinbase = True
            else:
                print("here 2 block")
                return False #only one coinbase per block
        
        for input in trans.inputList:
            UTXO_id = input.txid + str(input.idx)
            if UTXO_id in used_UTXOs:
                return False
            used_UTXOs.append(UTXO_id)

        if not verify_tx(trans):
            print("here 3 block")
            return False
        
        

        
    if block.BlockBody.getHash() != block.BlockHeader.merkleRoot:
        print("here 4 block")
        return False

    if not check_proof_of_work(block.getHash(), block.BlockHeader.targetDiff):
        print("here 5 block")
        return False
    
    return True


        

def check_proof_of_work(block_hash: str, targetDiff: int):
    if not block_hash or not targetDiff:
        return False
    block_hash_bytes = binascii.unhexlify(block_hash.encode())
    # print("block hash bytes: ", hex(int.from_bytes(block_hash_bytes, 'big')))
    # print("targetDiff: ", hex(bits_to_target(targetDiff)))
    if int.from_bytes(block_hash_bytes, 'big') < bits_to_target(targetDiff):
        return True
    return False

def target_to_bits(target: int):
    """
    converts from bitcoin target representation to compact bits representation
    :param target: int:  ex. 0x00000000000000000011d4f20000000000000000000000000000000000000000
    :return  int:
    """

    if target == 0:
        return 0
        
    MAX_TARGET = 0x0000FFFFFFFF0000000000000000000000000000000000000000000000000000
    target = min(target, MAX_TARGET)
    size = (target.bit_length() + 7) // 8
    mask64 = 0xffffffffffffffff

    if size <= 3:
        compact = (target & mask64) << (8 * (3 - size))
    else:
        compact = (target >> (8 * (size - 3))) & mask64

    if compact & 0x00800000:
        compact >>= 8
        size += 1
    assert compact == (compact & 0x007fffff)
    assert size < 256
    return compact | size << 24

def bits_to_target(bits: int):
    """
    converts from  bitcoin compact bits representation to target
    :param bits: int
    :return: int
    """
    if not bits:
        return 0
    
    # hex_bits = hex(bits)[2:]
    # exponent = int(hex_bits[:2], 16)
    # coefficient = int(hex_bits[2:], 16)
    # print(exponent)
    # return coefficient * 256 ** (exponent - 3)

    bits_bytes = bits.to_bytes(4, 'big')
    exponent = bits_bytes[0]
    coefficient = int.from_bytes(bits_bytes[1:], 'big')
    return coefficient * 256 ** (exponent - 3)

def verify_tx(tran: Transaction):
    if len(tran.inputList) == 0:
        return True


    inputAmount = 0

    UTXOutput_info_list = []
    for input in tran.inputList:
        UTXOutput_info = get_UTXO_index_info_parallel(input.txid, input.idx)
        if not UTXOutput_info:
            print('here 0 tx')
            return False

        trans_hash = UTXOutput_info['_id'][:64]
        idx = int(UTXOutput_info['_id'][64:])

        UTXOutput = getUTXO(trans_hash, idx)

        if not UTXOutput_info:
            print('here 1 tx')
            return False

        if UTXOutput_info['_id'] in UTXOutput_info_list:
            print('here 2 tx')
            return False
        
        UTXOutput_info_list.append(UTXOutput_info['_id'])
        
        if not verifyTransInput(input, UTXOutput, tran.hash):
            print('here 3 tx')
            return False

        inputAmount += UTXOutput.amount
    
    outputAmount = 0
    for output in tran.outputList:
        outputAmount += output.amount
    
    if outputAmount - inputAmount > 0:
        print('here 4 tx')
        return False


    return True

def verifyTransInput(input : TransactionInput, UTXOutput, tran_hash: str):
    if UTXOutput.script_type == ScriptType.P2PKH:
        return verifyP2PKH(input, UTXOutput, tran_hash)
    
    elif UTXOutput.script_type == ScriptType.P2MS:
        return verifyP2MS(input, tran_hash)

    return False

def verifyP2PKH(input : TransactionInput, UTXOutput, tran_hash: str):
    stack = [input.signature, input.publicKey]

    "OP_DUP"
    stack.append(stack[-1])
    "OP_HASH"
    temp = stack.pop()
    address = pubkey_to_address(temp)
    stack.append(address)
    "append address"
    stack.append(UTXOutput.recvAddress)

    "OP_EQUALVERIFY"
    outputPublickeyHash = stack.pop()
    inputPublickeyHash = stack.pop()
    if inputPublickeyHash != outputPublickeyHash:
        print('here 1 P2PKH')
        return False
    
    "OP_CHECKSIG"
    publickeyObject = ed25519.VerifyingKey(binascii.unhexlify(input.publicKey.encode()))
    # print("signature: ", input.signature)
    # print(len(input.signature))
    # print("tranasction hash: ",tran_hash)
    # print("input public key: ", input.publicKey)
    # print("publickeyObj: ", publickeyObject.to_bytes().hex())
    # print(publickeyObject.verify(binascii.unhexlify(input.signature.encode()), binascii.unhexlify(tran_hash.encode())))
    try:
        publickeyObject.verify(binascii.unhexlify(input.signature.encode()), binascii.unhexlify(tran_hash.encode()))
        return True
    except:
        return False

def verifyP2MS(input: TransactionInput, tran_hash: str):
    list_pubkeys = input.publicKey.split(' ')
    list_sigs = input.signature.split(' ')

    if len(list_pubkeys) != len(list_sigs):
        return False

    tx_hash = input.txid
    idx = int(input.idx)

    UTXOutput = getUTXO(tx_hash, idx)
    script = UTXOutput.recvAddress.split(' ')
    sigs_required = int(script[0])
    total_keys = int(script[1])
    list_addresses = script[2:]

    if sigs_required > len(list_pubkeys):
        return False

    count_sigs = 0
    for i in range(sigs_required):
        pubkey = list_pubkeys[i]
        pubkey_addr = pubkey_to_address(pubkey)

        for address in list_addresses:
            if pubkey_addr == address:
                list_addresses.remove(address)
                break
        else:
            return False

        publickeyObject = ed25519.VerifyingKey(binascii.unhexlify(pubkey.encode()))
        sig = list_sigs[i]
        try:
            publickeyObject.verify(binascii.unhexlify(sig.encode()), binascii.unhexlify(tran_hash.encode()))
            count_sigs += 1
            if count_sigs >= sigs_required:
                return True
        except:
            return False
    
    if count_sigs >= sigs_required:
        return True
    
    return False

# private_key = "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725"
# public_key = "0450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b23522cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6"
# address = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"
# pubkeyScript = "OP_DUP OP_HASH {} OP_EQUALVERIFY OP_CHECKSIG".format(address)

# private_key = "8EA7C27775BAADEE8CC4F0671C431D0399A4BD5D5F52BC15708AD4EDBD456EEF"
# public_key = "04A5B3B2DB2EB52C6481B791F7ABDED1A85F29810A3BB93C0E58AC36595C690BF7ADF9472E4A9AB86148427CB44A564618BEE2209890BB4269A3E9738F8F571CCD"
# address = "1Ap4JgMR3pCvNfFZ6z6FMoq9zprSSWPZfQ"
# pubkeyScript = "OP_DUP OP_HASH {} OP_EQUALVERIFY OP_CHECKSIG".format(address)

# privkeyObject = ecdsa.SigningKey.from_string(binascii.unhexlify(private_key.encode()), curve=ecdsa.SECP256k1, hashfunc= hashlib.sha256)
# print(privkeyObject.to_string().hex())

# pubkeyObject = ecdsa.VerifyingKey.from_string(binascii.unhexlify(public_key.encode()), curve=ecdsa.SECP256k1, hashfunc= hashlib.sha256)
# print(pubkeyObject.to_string().hex())
def pubkey_to_address(pubkey: str):
    hash1 = hashlib.sha256(pubkey.encode()).hexdigest()
    hash2 = hashlib.new('ripemd160', hash1.encode()).hexdigest()

    hash3 = hashlib.sha256(hash2.encode()).hexdigest()
    hash4 = hashlib.sha256(hash3.encode()).hexdigest()

    #first 4 bytes of hash4
    checksum = hash4[:8]

    result = hash2 + checksum

    return base58.b58encode(binascii.unhexlify(result)).decode()

def validateAddress(address):
    addr_decode = base58.b58decode(address).hex()


    hash = addr_decode[:len(addr_decode) - 8]

    checksum = addr_decode[len(addr_decode) - 8:]

    for i in range(2):
        hash = hashlib.sha256(hash.encode()).hexdigest()

    if hash[:8] == checksum:
        return True
    return False

def find_nonce(version, height, prevHash, merkleRoot, timeStamp, targetDiff):
    nonce = 0
    hash_value = hash(version, height, prevHash, merkleRoot, timeStamp, targetDiff, nonce)
    while not check_proof_of_work(hash_value, targetDiff):
        nonce += 1
        # print("nonce: ", nonce)
        hash_value = hash(version, height, prevHash, merkleRoot, timeStamp, targetDiff, nonce)
    
    # print(str({
    #         'version': version,
    #         'prevHash': prevHash,
    #         'merkleRoot': merkleRoot,
    #         'timeStamp ': timeStamp ,
    #         'targetDiff': targetDiff,
    #         'nonce': nonce,
    #     }))
    # print(hash_value)
    return nonce

def hash(version, height, prevHash, merkleRoot, timeStamp, targetDiff, nonce):
    text = json.dumps({
            'version': version,
            'height': height,
            'prevHash': prevHash,
            'merkleRoot': merkleRoot,
            'timeStamp': timeStamp ,
            'targetDiff': targetDiff,
            'nonce': nonce,
        }).encode()
    return hashlib.sha256(text).hexdigest()

# def genesis_block():
#     transInput = []
#     transOutput = [TransactionOutput(100000, "1L2DhfDNRyK2KLwX9PU4YWaevRmiT5sgHM")]
#     timeStamp = int(time.time())

#     trans = Transaction(transInput, transOutput, timeStamp)
#     body = BlockBody([trans])

#     version = 1
#     prevHash = "0000000000000000000000000000000000000000000000000000000000000000"
#     merkleRoot = body.getHash()
#     timeStamp = time.time()
#     targetDiff = 0x1f00ffff
#     nonce = find_nonce(version, prevHash, merkleRoot, timeStamp, targetDiff)
#     print('nonce: ', nonce)

#     header = BlockHeader(version, prevHash, merkleRoot, timeStamp, targetDiff, nonce)

#     block = Block(header, body)
#     print('block hash: ', block.getHash())
#     print("block header hash", block.BlockHeader.getHash())
#     print("int of hash: ", int.from_bytes(block.hash, "big"))

#     writeblock(block, 0)
#     add_tx_to_address_index(block, 0)
#     update_blockchain_info(0, block.hash, block.BlockHeader.targetDiff)

def get_fee(list_trans: list):
    inputAmount = 0
    outputAmount = 0
    for trans in list_trans:
        for input_idx, input in enumerate(trans.inputList):
            UTXOutput = getUTXO(input.txid, input.idx)
            inputAmount += UTXOutput.amount
        
        for output_idx, output in enumerate(trans.outputList):
            outputAmount += output.amount
    
    return inputAmount - outputAmount



def create_new_block(list_trans: list):
    blockchain_info = get_blockchain_info()

    height =  blockchain_info['height'] 
    prevBlockHash = blockchain_info['bestBlockHash']
    difficulty = blockchain_info['difficulty']

    fee = get_fee(list_trans)

    coinbaseTrans = Transaction([], [TransactionOutput(25 + fee, "8qUAkic2cyxyNGvHhPtN9DdvQ3FsouzYe")], int(time.time()))

    body = BlockBody([coinbaseTrans] + list_trans)

    version = 1
    prevHash = prevBlockHash
    merkleRoot = body.getHash()
    timeStamp = int(time.time())

    if height + 1 % 100 == 0:
        targetDiff = recalculateDifficulty()
    else:
        targetDiff = difficulty

    nonce = find_nonce(version, height + 1, prevHash, merkleRoot, timeStamp, targetDiff)

    header = BlockHeader(version, height + 1, prevHash, merkleRoot, timeStamp, targetDiff, nonce)
    
    block = Block(header, body)
    print('block hash: ', block.getHash())
    # print("block header hash", block.BlockHeader.getHash())
    # print("int of hash: ", int.from_bytes(block.hash.encode(), "big"))
    print("target Difficulty: ", block.BlockHeader.targetDiff)

    return block
    


def recalculateDifficulty():
    blockchain_info = get_blockchain_info()

    height =  blockchain_info['height'] 
    oldDiff = blockchain_info['difficulty']

    firstBlock_lastCluster = getblock(height + 1 - 100)
    lastBlock_lastCluster = getblock(height)

    timePassed = lastBlock_lastCluster.BlockHeader.timeStamp - firstBlock_lastCluster.BlockHeader.timeStamp

    newDiff = oldDiff * timePassed / 500

    newDiff = min(newDiff, 4*oldDiff)
    newDiff = max(newDiff, 1/4 * oldDiff)

    return newDiff


# block = getblock(0)
# print(sys.getsizeof(json.dumps(block.BlockHeader.toString())))
# print(block.BlockHeader.toString())
# print(block.BlockBody.toString())
# print(block.getHash())

# print(sys.getsizeof( int() ))

def isGenesisBlockExist():
    blockDataPath =  os.path.join(root_path, 'BlockData')
    blockClusterPath = os.path.join(blockDataPath, 'Cluster') + str(getBlockCluster(0))

    if not os.path.exists(blockClusterPath):
        return False
    
    blockPath = blockClusterPath + '/' + '{}.txt'.format(0)
    if not os.path.exists(blockPath):
        return False

    return True

def connectPeer():
    ClientSocket = socket.socket()
    host = '192.168.1.170'
    port = 12345

    # print('Trying to connect')
    try:
        ClientSocket.connect((host, port))
        return ClientSocket
    except socket.error as e:
        # print("no peer found")
        return None

def checkIsConnected(ClientSocket: socket.socket):
    try:
        data = transmitData('ping', [])
        ClientSocket.sendall(data.encode())
        ClientSocket.settimeout(5)
        ClientSocket.recv(65536)
        return True
    except socket.timeout:
        return False
    return False

def is_mempool_empty():
    return mydb['Mempool'].count_documents({}) == 0

def mining() -> Block:
    if not is_mempool_empty():
        result = list(mydb['Mempool'].find({}).limit(20))
        list_ids = [x['_id'] for x in result]
        mydb['Mempool'].delete_many({"_id": {"$in": list_ids}})

        #remove field  "_id"
        for each in result:
            each.pop("_id", None)
        

        transList = [Transaction.from_json(trans_json) for trans_json in result]

        used_UTXOs = []
        for trans in transList:
            remove = False
            for input in trans.inputList:
                UTXO_id = input.txid + str(input.idx)
                # print(UTXO_id)
                if UTXO_id in used_UTXOs:
                    remove = True
                
                used_UTXOs.append(UTXO_id)
            if not verify_tx(trans):
                remove = True
            
            if remove:
                transList.remove(trans)

        if transList != []:
            new_block = create_new_block(transList)
            height = get_blockchain_info()['height'] + 1
            writeblock(new_block, height)
            del_UTXO_from_address_index(new_block)
            add_UTXO_to_address_index(new_block, height)
            add_tx_to_address_index(new_block, height)
            update_blockchain_info(height, new_block.hash, new_block.BlockHeader.targetDiff)
            update_used_address(new_block)

            check_money_send_to_platform(new_block)
        
            print("new block mine successfuly")
            return new_block
    return None

def synchronize(ClientSocket):
    data = transmitData('getblockchaininfo', [])
    ClientSocket.sendall(data.encode())
    peer_blockchain_info = json.loads(ClientSocket.recv(65536).decode())
    self_blockchain_info = get_blockchain_info()

    if peer_blockchain_info['height'] <= self_blockchain_info['height']:
        print("blockchain is synchronized")
        return
    else:
        print("synchronizing")
        start = max(self_blockchain_info['height'] - 50, 0)
        end = self_blockchain_info['height']
        sync_start_height = -1
        while True:
            data = transmitData('getlistblockheaders', [start, end])

            ClientSocket.sendall(data.encode())
            list_header_json = json.loads(ClientSocket.recv(65536).decode()) #list header_json
            print("list header json: ", list_header_json)

            list_length = len(list_header_json)
            for i in range(list_length - 1, -1, -1):
                block = getblock(end - ((list_length - 1) - i))
                print("block hash: ", block.hash)
                print("block header hash: ", BlockHeader.from_json(list_header_json[i]).getHash())
                if block.hash == BlockHeader.from_json(list_header_json[i]).getHash():
                    sync_start_height = i + 1 # because i_th block hash is equal
                    break

            if sync_start_height != -1:
                break
            
            start = max(start - 50, 0)
            end = end - 50

        for i in range(peer_blockchain_info['height'], sync_start_height - 1, -1):
            block = getblock(i)
            if block != None:
                del_tx_from_address_index(block)
                undo_UTXO_from_address_index(block)
                undo_used_address(block)
                deleteBlock(i)

        #synchronize
        for i in range(sync_start_height, peer_blockchain_info['height'] + 1):
            data = transmitData('getblock', [i])
            try:
                ClientSocket.sendall(data.encode())
                block_json = json.loads(ClientSocket.recv(65536).decode())
            except:
                return
            block = Block.from_json(block_json)
            print("block hash: ", block.hash)
            print("verify block: ", verify_block(block))
            if verify_block(block):
                writeblock(block, i)
                del_UTXO_from_address_index(block)
                add_UTXO_to_address_index(block, i)
                add_tx_to_address_index(block, i)
                update_blockchain_info(i, block.hash, block.BlockHeader.targetDiff)
                update_used_address(block)
        
        print("finish synchronize")

def del_tx_from_address_index(block: Block):
    transList = block.BlockBody.transList
    for trans in transList:
        for input in trans.inputList:
            if len(input.publicKey.split(' ')) > 1:
                address = getTransOutput(input.txid, input.idx).recvAddress
            else:
                address = pubkey_to_address(input.publicKey)

            result = mydb['UserAddress'].find_one({"_id": address})
            
            if result:
                for each in result['list_trans']:
                    if each['trans_hash'] == trans.hash:
                        result['list_trans'].remove(each)

                if  result['list_UTXOs'] == [] and result['list_trans'] == []:
                    mydb['UserAddress'].delete_one({"_id": address})
                else:
                    mydb['UserAddress'].update_one({"_id": address}, {"$set": {"list_trans": result['list_trans']}}, upsert=True)

def add_tx_to_address_index(block: Block, blockHeight: int):
    transList = block.BlockBody.transList
    for trans in transList:
        for input in trans.inputList:
            if len(input.publicKey.split(' ')) > 1:
                address = getTransOutput(input.txid, input.idx).recvAddress
            else:
                address = pubkey_to_address(input.publicKey)

            result = mydb['UserAddress'].find_one({"_id": address})
            if result == None:
                result = {
                    "_id": address,
                    "list_trans": [{
                        'trans_hash': trans.hash,
                        'blockHeight': blockHeight
                    }],
                    "list_UTXOs": []
                }
            else:
                result['list_trans'].append({
                    'trans_hash': trans.hash,
                    'blockHeight': blockHeight
                })

            if  result['list_UTXOs'] == [] and result['list_trans'] == []:
                mydb['UserAddress'].delete_one({"_id": address})
            else:
                mydb['UserAddress'].update_one({"_id": address}, {"$set": {"list_UTXOs": result['list_UTXOs'], "list_trans": result['list_trans']}}, upsert=True)

def undo_UTXO_from_address_index(block: Block): 
    # used when revert synchronize
    transList = block.BlockBody.transList
    for trans in transList:
        for output_idx, output in enumerate(trans.outputList):
            address = output.recvAddress
            result = mydb['UserAddress'].find_one({"_id": address})

            for each in result['list_UTXOs']:
                if each['UTXO_id'] == trans.hash + str(output_idx):
                    result['list_UTXOs'].remove(each)
                    break
            if  result['list_UTXOs'] == [] and result['list_trans'] == []:
                mydb['UserAddress'].delete_one({"_id": address})
            else:
                mydb['UserAddress'].update_one({"_id": address}, {"$set": {"list_UTXOs": result['list_UTXOs']}}, upsert=True)


        for input_idx, input in enumerate(trans.inputList):
            address = getTransOutput(input.txid, input.idx).recvAddress
            UTXO_id = input.txid + str(input.idx)
            UTXO_blockHeight = get_tran_index_info_parallel(input.txid)['blockHeight']

            result = mydb['UserAddress'].find_one({"_id": address})

            if result == None:
                result = {
                    "_id": address,
                    "list_trans": [],
                    "list_UTXOs": [{
                        'UTXO_id': UTXO_id,
                        'blockHeight': UTXO_blockHeight
                    }]
                }
            else:
                result['list_UTXOs'].append({
                    'UTXO_id': UTXO_id,
                    'blockHeight': UTXO_blockHeight
                })

            result['list_UTXOs'].append({
                'UTXO_id': UTXO_id,
                'blockHeight': UTXO_blockHeight
            })

            mydb['UserAddress'].update_one({"_id": address}, {"$set": {"list_UTXOs": result['list_UTXOs'], "list_trans": result['list_trans']}}, upsert=True)

def del_UTXO_from_address_index(block: Block):
    transList = block.BlockBody.transList
    for trans in transList:
        for input_idx, input in enumerate(trans.inputList):
            address = getTransOutput(input.txid, input.idx).recvAddress
            UTXO_id = input.txid + str(input.idx)
            result = mydb['UserAddress'].find_one({"_id": address})
            
            for each in result['list_UTXOs']:
                if each['UTXO_id'] == UTXO_id:
                    result['list_UTXOs'].remove(each)
                    break
            if  result['list_UTXOs'] == [] and result['list_trans'] == []:
                mydb['UserAddress'].delete_one({"_id": address})
            else:
                mydb['UserAddress'].update_one({"_id": address}, {"$set": {"list_UTXOs": result['list_UTXOs']}}, upsert=True)

def add_UTXO_to_address_index(block: Block, blockHeight: int):
    transList = block.BlockBody.transList
    for trans in transList:
        for output_idx, output in enumerate(trans.outputList):
            address = output.recvAddress

            result = mydb['UserAddress'].find_one({"_id": address})
            if result == None:
                result = {
                    "_id": address,
                    "list_trans": [],
                    "list_UTXOs": [{
                        'UTXO_id': trans.hash + str(output_idx),
                        'blockHeight': blockHeight
                    }]
                }
            else:
                result['list_UTXOs'].append({
                    'UTXO_id': trans.hash + str(output_idx),
                    'blockHeight': blockHeight
                })

            mydb['UserAddress'].update_one({"_id": address}, {"$set": {"list_UTXOs": result['list_UTXOs'], "list_trans": result['list_trans']}}, upsert=True)

def update_used_address(block: Block):
    transList = block.BlockBody.transList
    for trans in transList:
        for input_idx, input in enumerate(trans.inputList):
            address = getTransOutput(input.txid, input.idx).recvAddress
            UTXO_id = input.txid + str(input.idx)
            UTXO_blockHeight = get_tran_index_info_parallel(input.txid)['blockHeight']

            mydb['UsedAddress'].update_one({'_id': address}, {"$set": {"_id": address}}, upsert=True)

def undo_used_address(block: Block):
    transList = block.BlockBody.transList
    for trans in transList:
        for input_idx, input in enumerate(trans.inputList):
            address = getTransOutput(input.txid, input.idx).recvAddress
            UTXO_id = input.txid + str(input.idx)
            UTXO_blockHeight = get_tran_index_info_parallel(input.txid)['blockHeight']

            mydb['UsedAddress'].delete_one({'_id': address})

if __name__ == "__main__":
    p = Pool(processes=2)

    isConnected = False

    start_time = time.time()

    last_mining_time = 0
    last_synchronize_time = 0
    last_trying_to_connect_time = 0
    last_ping = 0

    while True:
        now_time = time.time()
        
        if isConnected == False and now_time - last_trying_to_connect_time > 20:
            ClientSocket = connectPeer()
            if ClientSocket != None:
                isConnected = True
            else:
                isConnected = False
            last_trying_to_connect_time = now_time
        
        if isConnected and now_time - last_ping > 5:
            isConnected = checkIsConnected(ClientSocket)
            last_ping = now_time

        if now_time - last_mining_time > 5:
            new_block = mining()
            last_mining_time = now_time
        
            if new_block and isConnected:
                data = transmitData('submitblock', [new_block.toJSON()])
                ClientSocket.sendall(data.encode())
        
        if now_time - last_synchronize_time > 10 and isConnected:
            try:
                synchronize(ClientSocket)
                last_synchronize_time = now_time
            except:
                pass
        







