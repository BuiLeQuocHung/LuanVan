import socket, os, json, sys, ed25519
import base58
from _thread import *

from config import *
from Structure.Block import *
from DatabaseConnect.connect_database import *
from bitcoin import *
from update_balance_from_blockchain import add_new_address, widthdrawn_money

from itertools import repeat
from functools import reduce
from multiprocessing import Pool, Process





def threaded_client(connection):
    while True:
        data = connection.recv(65536)
        # print("========WTF=========")
        # print("data: ", data)
        # print("size of data: ", sys.getsizeof(data))
        if not data:
            break

        data_decode = json.loads(data.decode())
        # print("data_decode: ", data_decode)
        # print("size of data decode: ", sys.getsizeof(data_decode))
        
        # data_decode =
        # {
        #     'task': 1234,
        #     'param': [1234, ...]
        # }

        task = data_decode['task']
        # print(task)
        if task == 'ping':
            connection.sendall('ping'.encode())
        
        elif task == 'createaddress':
            entropy, userID = data_decode['param']
            add_new_address(entropy, userID)
        
        elif task == 'widthdrawn':
            amount, address = data_decode['param']
            widthdrawn_money(amount, address)

        elif task == 'addressexist':
            address = data_decode['param'][0]
            isExist = address_exist(address)
            connection.sendall(json.dumps(isExist).encode())
            pass

        elif task == 'getblock':
            blockHeight = data_decode['param'][0]
            block = getblock(blockHeight)
            connection.sendall(json.dumps(block.toJSON()).encode())

        elif task == 'getblockheader':
            blockHeight = data_decode['param'][0]
            blockheader = getblockheader(blockHeight)
            connection.sendall(json.dumps(blockheader.toJSON()).encode())

        elif task == 'gettransaction':
            trans_hash = data_decode['param'][0]
            transaction = getTrans(trans_hash)
            connection.sendall(json.dumps(transaction.toJSON()).encode())

        elif task == "getTransInfo":
            trans_hash = data_decode['param'][0]
            transaction_info = getTransInfo(trans_hash)
            # print('trans_info: ', transaction_info)
            connection.sendall(json.dumps(transaction_info).encode())
        
        elif task == 'getTransOutput':
            trans_hash, idx = data_decode['param']
            trans_output = getTransOutput(trans_hash, idx)
            connection.sendall(json.dumps(trans_output.toJSON()).encode())
        
        elif task == 'getUTXO':
            trans_hash, idx = data_decode['param']
            UTXOutput = getUTXO(trans_hash, idx)
            connection.sendall(json.dumps(UTXOutput.toJSON()).encode())

        elif task == 'getblockchaininfo':
            blockchain_info = get_blockchain_info()
            connection.sendall(json.dumps(blockchain_info).encode())

        elif task =='getaddressUTXO':
            address = data_decode['param'][0]
            result = get_addr_UTXO_parallel(address)
            connection.sendall(json.dumps(result).encode())

        elif task == 'getaddressTransactions':
            list_address = data_decode['param'][0]
            result = get_addr_trans_parallel(list_address)
            connection.sendall(json.dumps(result).encode())

        elif task == "getlistblockheaders":
            start, end = data_decode['param']
            # print("start", start, "end", end)
            result = getlistblockheaders(start, end)
            connection.sendall(json.dumps(result).encode())

        elif task == 'submitblock':
            block_json = data_decode['param'][0]
            block = Block.from_json(block_json)
            if verify_block(block):
                blockchain_info = get_blockchain_info()

                if blockchain_info: 
                    if block.BlockHeader.prevHash == blockchain_info['bestBlockHash']:
                        writeblock(block, blockchain_info['height'] + 1)
                        add_UTXO_to_address_index(block, blockchain_info['height'] + 1)
                        add_tx_to_address_index(block, blockchain_info['height'] + 1)
                        update_blockchain_info(blockchain_info['height'] + 1, block.hash, block.BlockHeader.targetDiff)
                        update_used_address(block)

        elif task =='submittransaction':
            trans_json = data_decode['param'][0]
            trans = Transaction.from_json(trans_json)
            if verify_tx(trans):
                trans_to_mempool(trans)
                


    connection.close()

def address_exist(address):
    if mydb['UsedAddress'].find_one({'_id': address}):
        return '1'
    return '0'

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
    # print('address: ', address)

    result =  list(reduce(lambda x,y : x + y,  p.starmap(get_addr_UTXO, zip(a, repeat(address))), []))

    #remove duplicate
    result = [json.dumps(x) for x in result]
    result = list(set(result))
    result = [json.loads(x) for x in result]

    return result

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
    # if address == "53WcwymbzuqvULhvzUxNopdMDr1f6BXYB":
    #     print(addr_UTXOs_index)

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
            # if address == "53WcwymbzuqvULhvzUxNopdMDr1f6BXYB":
            #     print('trans hash: ', trans.hash)
            if trans.hash == trans_hash:
                output_json = trans.outputList[idx].toJSON()
                output_json['_id'] = UTXO_id
                result.append(output_json)
                break
    # if address == "53WcwymbzuqvULhvzUxNopdMDr1f6BXYB":
    #     print(result)
    return result

def get_addr_trans_parallel(list_address):
    # print(list_address)
    result = list(reduce(lambda x,y : x + y, p.map(get_addr_trans, list_address), []))

    #remove duplicate
    result = [json.dumps(x) for x in result]
    result = list(set(result))
    result = [json.loads(x) for x in result]

    return result

def get_addr_trans(address):
    addr_trans_index = mydb['UserAddress'].find_one({'_id': address})
    # {
    #   _id: ...,
    #   list_trans: [{trans_hash, blockHeight}, ...]
    # }

    result = []
    if addr_trans_index == None:
        return result
    
    for each in addr_trans_index['list_trans']:
        trans_hash = each['trans_hash']
        blockHeight = each['blockHeight']
        
        block = getblock(blockHeight)
        for trans in block.BlockBody.transList:
            if trans.hash == trans_hash:
                result.append(trans.toJSONwithSignature())
                break
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
    print(start, end)
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
    
    deleteBlockIndex(block.hash())

    os.remove(blockPath)


def getTrans(tran_hash: str) -> Transaction:
    tran_index_info = get_tran_index_info_parallel(tran_hash)

    if not tran_index_info:
        return None

    blockHeight = tran_index_info['blockHeight']
    block = getblock(blockHeight)

    idx = tran_index_info['idx']
    transaction = block.BlockBody.transList[idx]

    return transaction

def getTransOutput(trans_hash: str, idx: int) -> TransactionOutput:
    trans = getTrans(trans_hash)
    return trans.outputList[idx]

def getTransInfo(tran_hash: str):
    trans_json = mydb['Mempool'].find_one({"_id": tran_hash})


    if trans_json:
        trans = Transaction.from_json(trans_json)
        trans_json['confirmation'] = -1
        trans_json['inputAmount'] = get_trans_input_amount(trans)
        return trans_json

    trans_index_info = get_tran_index_info_parallel(tran_hash)
    if not trans_index_info:
        return None

    trans = getTrans(tran_hash)
    trans_json = trans.toJSONwithSignature()
    blockchain_info = get_blockchain_info()
    trans_json['confirmation'] =  blockchain_info['height'] - trans_index_info['blockHeight']
    trans_json['inputAmount'] = get_trans_input_amount(trans)
    return trans_json


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
        return False

    checkCoinbase = False
    used_UTXOs = []
    for trans in block.BlockBody.transList:
        if len(trans.inputList) == 0:
            if not checkCoinbase:
                checkCoinbase = True
            else:
                print("here 2")
                return False #only one coinbase per block
        
        for input in trans.inputList:
            UTXO_id = input.txid + str(input.idx)
            if UTXO_id in used_UTXOs:
                return False
            used_UTXOs.append(UTXO_id)

        if not verify_tx(trans):
            print("here -1")
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
            print('here 0')
            return False

        trans_hash = UTXOutput_info['_id'][:64]
        idx = int(UTXOutput_info['_id'][64:])

        UTXOutput = getUTXO(trans_hash, idx)

        if not UTXOutput_info:
            print('here 1')
            return False

        if UTXOutput_info in UTXOutput_info_list:
            print('here 2')
            return False
        
        UTXOutput_info_list.append(UTXOutput_info)
        
        if not verifyTransInput(input, UTXOutput, tran.hash):
            print('here 3')
            return False

        inputAmount += UTXOutput.amount
    
    outputAmount = 0
    for output in tran.outputList:
        outputAmount += output.amount
    
    if outputAmount - inputAmount > 0:
        print('here 4')
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
        print('here 6')
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

# privkeyObject = ed25519.SigningKey.from_string(binascii.unhexlify(private_key.encode()), curve=ed25519.SECP256k1, hashfunc= hashlib.sha256)
# print(privkeyObject.to_string().hex())

# pubkeyObject = ed25519.VerifyingKey.from_string(binascii.unhexlify(public_key.encode()), curve=ed25519.SECP256k1, hashfunc= hashlib.sha256)
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

    # print('hash value int: ',int.from_bytes(binascii.unhexlify(hash_value), 'big'))
    # print('targetDiff: ', bits_to_target(targetDiff))
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

def genesis_block():
    transInput = []
    transOutput = [TransactionOutput(1000000, "8qUAkic2cyxyNGvHhPtN9DdvQ3FsouzYe"), TransactionOutput(1000000, "s44pNAueQYJPved5Ad9fkfJ1qkSr3hGV")]
    timeStamp = 1

    trans = Transaction(transInput, transOutput, timeStamp)
    body = BlockBody([trans])

    version = 1
    height = 0
    prevHash = "0000000000000000000000000000000000000000000000000000000000000000"
    merkleRoot = body.getHash()
    timeStamp = 1
    targetDiff = 0x1f00ffff
    nonce = find_nonce(version, height, prevHash, merkleRoot, timeStamp, targetDiff)

    header = BlockHeader(version, height, prevHash, merkleRoot, timeStamp, targetDiff, nonce)

    block = Block(header, body)
    # print('block hash: ', block.getHash())
    # print("block header hash", block.BlockHeader.getHash())
    # print("int of hash: ", int.from_bytes(binascii.unhexlify(block.hash.encode()), "big"))
    # print("target Difficulty: ", bits_to_target(block.BlockHeader.targetDiff))
    print(block.toJSON())
    writeblock(block, 0)
    add_UTXO_to_address_index(block, 0)
    add_tx_to_address_index(block, 0)
    update_blockchain_info(0, block.hash, block.BlockHeader.targetDiff)
    update_used_address(block)

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

def get_trans_input_amount(trans: Transaction):
    inputAmount = 0
    for input_idx, input in enumerate(trans.inputList):
        trans_output = getTransOutput(input.txid, input.idx) 
        inputAmount += trans_output.amount
        
    return inputAmount

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

# def is_mempool_empty():
#     return mydb['Mempool'].count_documents({}) == 0

# def autoMining():
#     while True:
#         if not is_mempool_empty():
#             result = list(mydb['Mempool'].find({}).limit(20))
#             list_ids = [x['_id'] for x in result]
#             mydb['Mempool'].delete_many({"_id": {"$in": list_ids}})

#             #remove filed  "_id"
#             for each in result:
#                 each.pop("_id", None)
#                 print(each)
            

#             transList = [Transaction.from_json(trans_json) for trans_json in result]
#             # for trans in transList:
#             #     if not verify_tx(trans):
#             #         transList.remove(trans)

#             if transList != []:
#                 new_block = create_new_block(transList)
#                 height = get_blockchain_info()['height'] + 1
#                 writeblock(new_block, height)
#                 update_blockchain_info()
            
#         time.sleep(5)

def add_tx_to_address_index(block: Block, blockHeight: int):
    transList = block.BlockBody.transList
    for trans in transList:
        for input in trans.inputList:
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
                if 'list_trans' not in result:
                    result['list_trans'] = []

                result['list_trans'].append({
                    'trans_hash': trans.hash,
                    'blockHeight': blockHeight
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
                if 'list_UTXOs' not in result:
                    result['list_UTXOs'] = []

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


if __name__ == "__main__":
    ServerSocket = socket.socket()
    host = '192.168.49.37'
    port = 12345
    ThreadCount = 0
    try:
        ServerSocket.bind((host, port))
    except socket.error as e:
        print(str(e))
    print('Waitiing for a Connection..')
    ServerSocket.listen(5)



    p = Pool(processes=2)

    if not isGenesisBlockExist():
        print("create genesis block")
        genesis_block()
    
    while True:
        Client, address = ServerSocket.accept()
        print('Connected to: ' + address[0] + ':' + str(address[1]))
        start_new_thread(threaded_client, (Client, ))
        # threaded_client(Client)
        ThreadCount += 1
        print('Thread Number: ' + str(ThreadCount))
    
    p.close()
    ServerSocket.close()

