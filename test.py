import hdwallet
from FullNode.Structure.Block import *
import os
from FullNode.config import *

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
        temp = file.read()
        block = Block.from_binary(temp)

    # return Block.from_json(block_json)
    return block

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
    print('bits bytes: ', bits_bytes.hex())
    exponent = bits_bytes[0]
    coefficient = int.from_bytes(bits_bytes[1:], 'big')
    return coefficient * 256 ** (exponent - 3)

# block_1 = getblock(1)

# # with open('hahaha.txt', 'w+') as file:
# #     json.dump(block_1.toJSON(), file, sort_keys=True, indent= 4, separators=(', ', ': '))

# print('bits to target: ', (bits_to_target(block_1.BlockHeader.targetDiff)))
# print(block_1.BlockBody.transList[1].inputList[0].toJSONwithSignature())
# input_bytes = block_1.BlockBody.transList[1].inputList[0].to_binary()
# print('len input: ', input_bytes[:1].hex())
# print('txid: ', input_bytes[1:33].hex())
# print('idx: ', input_bytes[33:35].hex())
# print('pubkey: ', input_bytes[35:67].hex())
# print('sig: ', input_bytes[67:].hex())

# a = "123"

# with open('hahaha.txt', 'wb+') as file:
#     file.write(a.encode())

# with open('hahaha.txt', 'rb') as file:
#     temp = file.read()
#     print(len(temp))

# =============================================================================
# block = getblock(1)
# print(block.getHash())
# with open('hahaha.txt', 'w+') as file:
#     json.dump(block.toJSON(), file, sort_keys=True, indent= 4, separators=(', ', ': '))

# print(block.to_binary()[82: 82 + 47].hex())
#=============================================================================

# trans_bytes = block.BlockBody.transList[1].to_binary()

# print('===================')
# output_bytes = block.BlockBody.transList[1].outputList[0].to_binary()

# checkpoint = 1
# script_type_len = int.from_bytes(output_bytes[checkpoint: checkpoint + 1], 'big')
# print('script type: ',script_type_len)
# checkpoint += 1
# script_type = output_bytes[checkpoint: checkpoint + script_type_len].hex()
# print('script type: ', script_type)
# checkpoint += script_type_len
# amount = output_bytes[checkpoint: checkpoint + 6].hex()
# print('amount: ', amount)
# checkpoint += 6
# address = output_bytes[checkpoint:].hex()
# print('address: ', address)

# print(int.to_bytes(0, 1, 'big').hex())

# checkpoint = 0
# len_inputlist = int.from_bytes(trans_bytes[checkpoint: checkpoint + 1], 'big')
# checkpoint += 1
# inputList = trans_bytes[checkpoint: checkpoint + len_inputlist * 130]
# checkpoint += len_inputlist * 130

# len_outputlist = int.from_bytes(trans_bytes[checkpoint: checkpoint + 1], 'big')
# checkpoint += 1
# outputList_start = checkpoint
# for i in range(len_outputlist):
#     len_output = int.from_bytes(trans_bytes[checkpoint: checkpoint + 1], 'big')
#     checkpoint += 1
#     checkpoint += len_output
# outputList = trans_bytes[outputList_start: checkpoint]

# timeStamp = trans_bytes[checkpoint: checkpoint + 4]

# print(len_inputlist.to_bytes(1, 'big').hex())
# print('inputList: ')
# print(inputList.hex())

# print(len_outputlist.to_bytes(1, 'big').hex())
# print('outputList: ')
# print(outputList.hex())

# print('timeStamp: ')
# print(timeStamp.hex())

def CKDpriv_hardened(k, c, i: int, n: int):
    text = "{}{}{}".format(c, k, i)
    hash_value = hashlib.sha512(text.encode()).hexdigest()
    left, right = hash_value[:256], hash_value[256:]

    if int(left, 16) >= n:
        return None

    privKey = (int(left, 16) + int(k, 16)) % n 
    chaincode = right

    if privKey == 0:
        return None

    return privKey, chaincode


# print(65535 * 2**224)
# temp = 65535 * 2**224
# print(len(hex(temp)))
# print(hex(temp))

# print(len(hex(bits_to_target(520159231))))
# print(len("ffff00000000000000000000000000000000000000000000000000000000"))

# from hdwallet import HDWallet
# from hdwallet.utils import generate_entropy
# from hdwallet.symbols import BTC as SYMBOL

# STRENGTH: int = 128  # Default is 128
# LANGUAGE: str = "english"  # Default is english
# ENTROPY: str = generate_entropy(strength=STRENGTH)
# PASSPHRASE: str = None  # "meherett"

# print(ENTROPY)

# hd_wallet: HDWallet = HDWallet(symbol=SYMBOL, use_default_path=False)
# hd_wallet.from_entropy(
#     entropy=ENTROPY, language=LANGUAGE, passphrase=PASSPHRASE
# )

print(json.dumps('1'))