import binascii
import enum
import  hashlib, json
from tabnanny import check
import numpy as np

class BaseTransactionInput:
    def __init__(self, txid, idx):
        self.txid = txid
        self.idx = idx

class TransactionInput(BaseTransactionInput):
    def __init__(self, txid: str, idx: int,  publicKey, signature = ''):
        super().__init__(txid, idx)

        self.publicKey = publicKey
        self.signature = signature
    
    
    def toJSON(self):
        return {
            'txid': self.txid,
            'idx': self.idx,
            'publicKey': self.publicKey
        }

    def toJSONwithSignature(self):
        return {
            'txid': self.txid,
            'idx': self.idx,
            'publicKey': self.publicKey,
            'signature': self.signature
        }

    def to_binary(self):
        byte_array = bytearray()

        txid_bytes = binascii.unhexlify(self.txid.encode()) # 32 bytes
        idx_bytes = int.to_bytes(self.idx, 2, 'big') # 2 bytes
        pubkey_bytes = binascii.unhexlify(self.publicKey.encode()) # 32 bytes
        signature_bytes = binascii.unhexlify(self.signature.encode()) #64 bytes

        byte_array.extend(txid_bytes)
        byte_array.extend(idx_bytes)
        byte_array.extend(pubkey_bytes)
        byte_array.extend(signature_bytes)

        return bytes(byte_array)

    @staticmethod
    def from_binary(input_bytes: bytes):
        # 130 bytes total
        txid = input_bytes[:32].hex()
        idx = int.from_bytes(input_bytes[32:34], 'big')
        public_key = input_bytes[34:66].hex()
        signature = input_bytes[66:].hex()

        return TransactionInput(txid, idx, public_key, signature)

    @staticmethod
    def from_json(input_json):
        txid = input_json['txid']
        idx = input_json['idx']
        publicKey = input_json['publicKey']
        signature = input_json['signature']
        return TransactionInput(txid, idx, publicKey, signature)

class ScriptType(enum.IntEnum):
    P2PKH = 1


class BaseTransactionOutput:
    def __init__(self, amount):
        self.amount = amount

class TransactionOutput(BaseTransactionOutput):
    def __init__(self, amount: float, recvAddress: str, script_type = ScriptType.P2PKH):
        super().__init__(amount)
        self.recvAddress = recvAddress
        self.script_type = script_type

    
    def toJSON(self):
        return {
            'amount': self.amount,
            'recvAddress': self.recvAddress,
            'script_type': self.script_type
        }
    
    def to_binary(self):
        byte_array = bytearray()

        script_type_bytes = int.to_bytes(self.script_type, 1, 'big')
        amount_bytes = int.to_bytes(self.amount, 6, 'big') # 6 bytes
        address_bytes = self.recvAddress.encode()

        byte_array.extend(script_type_bytes)
        byte_array.extend(amount_bytes)
        byte_array.extend(address_bytes)

        return bytes(byte_array)

    @staticmethod
    def from_binary(output_bytes: bytes):
        checkpoint = 0
        script_type = int.from_bytes(output_bytes[checkpoint: checkpoint + 1], 'big')
        checkpoint += 1
        amount = int.from_bytes(output_bytes[checkpoint: checkpoint + 6], 'big')
        checkpoint += 6
        address = output_bytes[checkpoint:].decode()

        return TransactionOutput(amount, address, script_type)
    
    @staticmethod
    def from_json(output_json):
        amount = output_json['amount']
        recvAddress = output_json['recvAddress']
        script_type = output_json['script_type']
        return TransactionOutput(amount, recvAddress, script_type)


class Transaction:
    def __init__(self, inputList: list, outputList: list, timeStamp: int):
        self.inputList = inputList
        self.outputList = outputList

        self.time = timeStamp
        self.hash = self.getHash()


    def getHash(self):
        text = json.dumps(self.toJSON()).encode()
        return hashlib.sha256(text).hexdigest()

    def toJSON(self):
        inputList = []
        for each in self.inputList:
            inputList.append(each.toJSON())
        
        outputList = []
        for each in self.outputList:
            outputList.append(each.toJSON())

        return {
            'txin': inputList,
            'txout': outputList,
            'time': self.time,
        }
    
    def toJSONwithSignature(self):
        inputList = []
        for each in self.inputList:
            inputList.append(each.toJSONwithSignature())
        
        outputList = []
        for each in self.outputList:
            outputList.append(each.toJSON())

        return {
            'txin': inputList,
            'txout': outputList,
            'time': self.time,
        }
    
    @staticmethod
    def from_json(trans_json):
        inputList = []
        for input_json in trans_json['txin']:
            inputList.append(TransactionInput.from_json(input_json))
        
        outputList = []
        for output_json in trans_json['txout']:
            outputList.append(TransactionOutput.from_json(output_json))

        time = trans_json['time']
        return Transaction(inputList, outputList, time)

    def to_binary(self):
        byte_array = bytearray()

        len_inputList_bytes = int.to_bytes(len(self.inputList), 1, 'big')
        byte_array.extend(len_inputList_bytes)
        for input in self.inputList:
            temp = input.to_binary()
            byte_array.extend(temp)

        len_outputList_bytes = int.to_bytes(len(self.outputList), 1, 'big')
        byte_array.extend(len_outputList_bytes)
        for output in self.outputList:
            temp = output.to_binary()
            byte_array.extend(int.to_bytes(len(temp), 1, 'big')) # len output
            byte_array.extend(temp)

        time_bytes = int.to_bytes(self.time, 4, 'big')
        byte_array.extend(time_bytes)

        return bytes(byte_array)

    @staticmethod
    def from_binary(trans_bytes):
        checkpoint = 0
        len_inputlist = int.from_bytes(trans_bytes[checkpoint: checkpoint + 1], 'big')
        checkpoint += 1
        inputList = []
        for i in range(len_inputlist):
            input_bytes = trans_bytes[checkpoint: checkpoint + 130]
            input = TransactionInput.from_binary(input_bytes) 
            checkpoint += 130
            inputList.append(input)
        
        len_outputlist = int.from_bytes(trans_bytes[checkpoint: checkpoint + 1], 'big')
        checkpoint += 1
        outputList = []
        for i in range(len_outputlist):
            len_output = int.from_bytes(trans_bytes[checkpoint: checkpoint + 1], 'big')
            checkpoint += 1
            output_bytes = trans_bytes[checkpoint: checkpoint + len_output]
            output = TransactionOutput.from_binary(output_bytes) 
            checkpoint += len_output
            outputList.append(output)

        timeStamp = int.from_bytes(trans_bytes[checkpoint: checkpoint + 4], 'big')

        return Transaction(inputList, outputList, timeStamp)


