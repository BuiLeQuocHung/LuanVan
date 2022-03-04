import socket, os, json, ecdsa
from _thread import *

from config import *
from Structure.Block import *
from DatabaseConnect.connect_database import *
from bitcoin import *

from itertools import repeat
from functools import reduce
from multiprocessing import Pool
from bson import ObjectId



def trans_to_mempool(trans: Transaction):
    mydb['Mempool'].insert_one(trans.toJSONwithSignature())

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
    return BlockColl.find_one({"_id": block_hash})

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
    
    with open(blockPath, 'r') as file:
        block_json = json.load(file)

    return Block.from_json(block_json)

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
    with open(blockPath, 'w+') as file:
        json.dump(block.toJSON(), file, indent= 4, separators=(', ', ': '))

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
    BlockColl.insert_one({"_id": block_hash, "blockHeight": blockHeight})

def deleteBlockIndex(block_hash):
    BlockColl.delete_one({"_id": block_hash})

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
            UTXOutput = getUTXO(input.txid, input_idx)
            writeUTXO(UTXOutput, input.txid, input_idx, blockHeight)

        deleteTrans(tran.hash)
    
    deleteBlockIndex(block.hash())

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

def getUTXO(tran_hash: str, idx: int):
    transaction = getTrans(tran_hash)
    UTXOutput = transaction.outputList[idx]

    return UTXOutput

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
        "address": UTXO.recvAddress,
        "amount": UTXO.amount,
        "script_type": UTXO.script_type
    }

    mydb[a[collection_index]].insert_one(record)

def verify_block(block: Block):
    if len(block.BlockBody.transList) == 0:
        return False

    checkCoinbase = False
    for trans in block.BlockBody.transList:
        if len(trans.inputList) == 0:
            if not checkCoinbase:
                checkCoinbase = True
            else:
                return False #only one coinbase per block

        if not verify_tx(trans):
            return False

        
    if block.BlockBody.getHash() != block.BlockHeader.merkleRoot:
        return False

    if not check_proof_of_work(block.getHash(), block.BlockHeader.targetDiff):
        return False
    
    return True


        

def check_proof_of_work(block_hash: str, targetDiff: int):
    if not block_hash or not targetDiff:
        return False
    block_hash_bytes = binascii.unhexlify(block_hash.encode())
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
            return False

        if UTXOutput_info in UTXOutput_info_list:
            return False
        
        UTXOutput_info_list.append(UTXOutput_info)
        
        if not verifyTransInput(input, UTXOutput_info, tran.hash):
            return False

        inputAmount += UTXOutput_info['amount']
    
    outputAmount = 0
    for output in tran.outputList:
        outputAmount += output.amount
    
    if outputAmount - inputAmount > 0:
        return False


    return True

def verifyTransInput(input : TransactionInput, UTXOutput_info, tran_hash: str):
    if UTXOutput_info['script_type'] == 'P2PKH':
        return verifyP2PKH(input, UTXOutput_info, tran_hash)

    return False

def verifyP2PKH(input : TransactionInput, UTXOutput_info, tran_hash: str):
    stack = [input.signature, input.publicKey]

    "OP_DUP"
    stack.append(stack[-1])
    "OP_HASH"
    temp = stack.pop()
    address = pubkey_to_address(temp)
    stack.append(address)
    "append address"
    stack.append(UTXOutput_info['address'])

    "OP_EQUALVERIFY"
    outputPublickeyHash = stack.pop()
    inputPublickeyHash = stack.pop()
    if inputPublickeyHash != outputPublickeyHash:
        return False
    
    "OP_CHECKSIG"
    publickeyObject = ecdsa.VerifyingKey.from_string(binascii.unhexlify(input.publicKey.encode()), curve = ecdsa.SECP256k1, hashfunc= hashlib.sha256)
    # print("signature: ", input.signature)
    # print("tranasction hash: ",tran_hash)
    # print("public key: ", input.publicKey)
    return publickeyObject.verify_digest(binascii.unhexlify(input.signature.encode()), binascii.unhexlify(tran_hash.encode()))



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


def find_nonce(version, prevHash, merkleRoot, timeStamp, targetDiff):
    nonce = 0
    hash_value = hash(version, prevHash, merkleRoot, timeStamp, targetDiff, nonce)
    while not check_proof_of_work(hash_value, targetDiff):
        nonce += 1
        hash_value = hash(version, prevHash, merkleRoot, timeStamp, targetDiff, nonce)
    
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

def hash(version, prevHash, merkleRoot, timeStamp, targetDiff, nonce):
    text = str({
            'version': version,
            'prevHash': prevHash,
            'merkleRoot': merkleRoot,
            'timeStamp ': timeStamp ,
            'targetDiff': targetDiff,
            'nonce': nonce,
        }).encode()
    return hashlib.sha256(text).hexdigest()

def genesis_block():
    transInput = []
    transOutput = [TransactionOutput(100000, "1L2DhfDNRyK2KLwX9PU4YWaevRmiT5sgHM")]
    timeStamp = time.time()

    trans = Transaction(transInput, transOutput, timeStamp)
    body = BlockBody([trans])

    version = 1
    prevHash = "0000000000000000000000000000000000000000000000000000000000000000"
    merkleRoot = body.getHash()
    timeStamp = time.time()
    targetDiff = 0x1f00ffff
    nonce = find_nonce(version, prevHash, merkleRoot, timeStamp, targetDiff)
    print('nonce: ', nonce)

    header = BlockHeader(version, prevHash, merkleRoot, timeStamp, targetDiff, nonce)

    block = Block(header, body)
    print('block hash: ', block.getHash())
    print(block.toJSON()['header'])

    writeblock(block, 0)
    update_blockchain_info(0, block.hash, block.BlockHeader.targetDiff)

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

    coinbaseTrans = Transaction([], [TransactionOutput(25 + fee, "1L2DhfDNRyK2KLwX9PU4YWaevRmiT5sgHM")], time.time())

    body = BlockBody([coinbaseTrans] + list_trans)

    version = 1
    prevHash = prevBlockHash
    merkleRoot = body.getHash()
    timeStamp = time.time()

    if height + 1 % 100 == 0:
        targetDiff = recalculateDifficulty()
    else:
        targetDiff = difficulty

    nonce = find_nonce(version, prevHash, merkleRoot, timeStamp, targetDiff)

    header = BlockHeader(version, prevHash, merkleRoot, timeStamp, targetDiff, nonce)

    block = Block(header, body)
    return block
    


def recalculateDifficulty():
    blockchain_info = get_blockchain_info()

    height =  blockchain_info['height'] 
    oldDiff = blockchain_info['difficulty']

    firstBlock_lastCluster = getblock(height + 1 - 100)
    lastBlock_lastCluster = getblock(height)

    timePassed = lastBlock_lastCluster.BlockHeader.timeStamp - firstBlock_lastCluster.BlockHeader.timeStamp

    newDiff = oldDiff * timePassed / 500

    newDiff = min(newDiff, oldDiff + 50)
    newDiff = max(newDiff, oldDiff - 50)

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
    host = '127.0.0.1'
    port = 12345
    while True:
        print('Trying to connection')
        try:
            ClientSocket.connect((host, port))
            break
        except socket.error as e:
            print("server is not online")
        time.sleep(5)
    return ClientSocket


def is_mempool_empty():
    return mydb['Mempool'].count_documents({}) == 0

def mining() -> Block:
    if not is_mempool_empty():
        result = list(mydb['Mempool'].find({}).limit(20))
        list_ids = [x['_id'] for x in result]
        mydb['Mempool'].delete_many({"_id": {"$in": list_ids}})

        #remove filed  "_id"
        for each in result:
            each.pop("_id", None)
        

        transList = [Transaction.from_json(trans_json) for trans_json in result]
        for trans in transList:
            if not verify_tx(trans):
                transList.remove(trans)

        if transList != []:
            new_block = create_new_block(transList)
            height = get_blockchain_info()['height'] + 1
            writeblock(new_block, height)
            update_blockchain_info(height, new_block.hash, new_block.BlockHeader.targetDiff)
        
        print("new block mine successfuly")
        return new_block


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
        start = self_blockchain_info['height'] - 50
        end = self_blockchain_info['height']
        sync_start_height = -1
        while True:
            data = transmitData('getlistblockheaders', [start, end])

            ClientSocket.sendall(data.encode())
            list_header_json = json.loads(ClientSocket.recv(65536).decode()) #list header_json
            # print(list_header_json)

            list_length = len(list_header_json)
            for i in range(list_length - 1, -1, -1):
                block = getblock(end - ((list_length - 1) - i))
                if block.hash == BlockHeader.from_json(list_header_json[i]).getHash():
                    sync_start_height = i + 1 # because i_th block hash is equal
                    break

            if sync_start_height != -1:
                break
            
            start = start - 50
            end = end - 50

        for i in range(peer_blockchain_info['height'], sync_start_height - 1, -1):
            deleteBlock(i)

        #synchronize
        for i in range(sync_start_height, peer_blockchain_info['height'] + 1):
            data = transmitData('getblock', [i])
            ClientSocket.sendall(data.encode())
            block_json = json.loads(ClientSocket.recv(65536).decode())
            block = Block.from_json(block_json)
            if verify_block(block):
                writeblock(block, i)
                update_blockchain_info(i, block.hash, block.BlockHeader.targetDiff)
        
        print("finish synchronize")    

if __name__ == "__main__":
    p = Pool(processes=2)
    ClientSocket = connectPeer()

    start_time = time.time()
    last_mining_time = start_time
    last_synchronize_time = start_time

    while True:
        now_time = time.time()
        if now_time - last_mining_time > 5:
            new_block = mining()
            last_mining_time = now_time
        
            if new_block:
                data = transmitData('submitblock', [new_block.toJSON()])
                ClientSocket.sendall(data.encode())
        
        if now_time - last_synchronize_time > 30:
            synchronize(ClientSocket)
            last_synchronize_time = now_time
        
        







