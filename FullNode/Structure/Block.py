import hashlib, pickle, string, sys, time
from datetime import *
from .Transaction import *
from copy import deepcopy




class BlockHeader:
    version: int
    prevHash: str
    merkleRoot: str
    timeStamp : float
    targetDiff: int
    nonce: int

    def __init__(self,version, prevHash, merkleRoot, timeStamp, targetDiff, nonce):
        self.version = version
        self.prevHash = prevHash
        self.merkleRoot = merkleRoot
        self.timeStamp  = timeStamp 
        self.targetDiff = targetDiff
        self.nonce = nonce

    def toJSON(self):
        return {
            'version': self.version,
            'prevHash': self.prevHash,
            'merkleRoot': self.merkleRoot,
            'timeStamp': self.timeStamp ,
            'targetDiff': self.targetDiff,
            'nonce': self.nonce,
        }

    def getHash(self):
        text = json.dumps(self.toJSON()).encode()
        return hashlib.sha256(text).hexdigest()

    @staticmethod
    def from_json(header_json):
        version = header_json["version"]
        prevHash = header_json["prevHash"]
        merkleRoot = header_json["merkleRoot"]
        timeStamp  = header_json["timeStamp"] 
        targetDiff = header_json["targetDiff"]
        nonce = header_json["nonce"]
        return BlockHeader(version, prevHash, merkleRoot, timeStamp, targetDiff, nonce)

class BlockBody:
    def __init__(self, transList):
        self.transList = transList

    def toJSON(self):
        transList = []
        for each in self.transList:
            transList.append(each.toJSONwithSignature())

        return {
            'transactions' : transList
        }

    def getHash(self):
        hash_list = []
        for each in self.transList:
            hash_list.append(each.getHash())

        while len(hash_list) != 1:
            if len(hash_list) % 2 == 1:
                last_hash = deepcopy(hash_list[-1])
                hash_list.append(last_hash)

            new_hash_list = []
            for i in range(len(hash_list) // 2):
                text = f'{hash_list[2*i]}{hash_list[2*i + 1]}'.encode()
                hash_value = hashlib.sha256(text).hexdigest()
                new_hash_list.append(hash_value)
                
            hash_list = new_hash_list

        return hash_list[0]

    def from_json(body_json):
        transList = []
        for trans_json in body_json['transactions']:
            transList.append(Transaction.from_json(trans_json))

        return BlockBody(transList)


class Block:
    def __init__(self, BlockHeader: BlockHeader, BlockBody: BlockBody):
        self.BlockHeader = BlockHeader
        self.BlockBody = BlockBody

        self.hash = self.getHash()

    def getHash(self):
        text = json.dumps(self.BlockHeader.toJSON()).encode()
        return hashlib.sha256(text).hexdigest()
    
    def toJSON(self):
        return {
            'header': self.BlockHeader.toJSON(),
            'body': self.BlockBody.toJSON()
        }

    @staticmethod
    def from_json(block_json):
        header = BlockHeader.from_json(block_json['header'])
        body = BlockBody.from_json(block_json['body'])
        return Block(header, body)

    def to_binary(self):
        byte_array = bytearray()

        version_bytes = int.to_bytes(self.BlockHeader.version, 4, 'big') # 4 bytes
        prevhash_bytes = binascii.unhexlify(self.BlockHeader.prevHash.encode()) # 32 bytes
        merkleroot_bytes = binascii.unhexlify(self.BlockHeader.merkleRoot.encode()) # 32 bytes
        timestamp_bytes = int.to_bytes(self.BlockHeader.timeStamp, 4, 'big') # 4 bytes
        targetdiff_bytes = int.to_bytes(self.BlockHeader.targetDiff, 4, 'big') # 4 bytes
        nonce = int.to_bytes(self.BlockHeader.nonce, 4, 'big') # 4 bytes

        byte_array.extend(version_bytes)
        byte_array.extend(prevhash_bytes)
        byte_array.extend(merkleroot_bytes)
        byte_array.extend(timestamp_bytes)
        byte_array.extend(targetdiff_bytes)
        byte_array.extend(nonce)

        number_of_trans_bytes = int.to_bytes(len(self.BlockBody.transList), 2, 'big')
        byte_array.extend(number_of_trans_bytes)

        for trans in self.BlockBody.transList:
            trans_bytes = trans.to_binary()
            byte_array.extend(trans_bytes)

        print(bytes(byte_array))
        return bytes(byte_array)
        
    
    @staticmethod
    def from_binary(block_bytes):
        
        checkpoint = 0
        version = int.from_bytes(block_bytes[checkpoint: checkpoint + 4], 'big')
        checkpoint += 4
        prevHash = block_bytes[checkpoint: checkpoint + 32].hex()
        checkpoint += 32
        merkleRoot = block_bytes[checkpoint: checkpoint + 32].hex()
        checkpoint += 32
        timeStamp = int.from_bytes(block_bytes[checkpoint: checkpoint + 4], 'big')
        checkpoint += 4
        targetDiff = int.from_bytes(block_bytes[checkpoint: checkpoint + 4], 'big')
        checkpoint += 4
        nonce = int.from_bytes(block_bytes[checkpoint: checkpoint + 4], 'big')
        checkpoint += 4

        len_translist = int.from_bytes(block_bytes[checkpoint: checkpoint + 2], 'big')
        checkpoint += 2
        transList = []
        for i in range(len_translist):
            trans_len = int.from_bytes(block_bytes[checkpoint: checkpoint + 2], 'big')
            checkpoint += 2
            trans_bytes = block_bytes[checkpoint: checkpoint + trans_len]
            trans = Transaction.from_binary(trans_bytes)
            checkpoint += trans_len
            transList.append(trans)

        header = BlockHeader(version, prevHash, merkleRoot, timeStamp, targetDiff, nonce)
        body = BlockBody(transList)

        return Block(header, body)
        

