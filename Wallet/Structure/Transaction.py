import  hashlib, json
import numpy as np

class BaseTransactionInput:
    def __init__(self, txid, idx):
        self.txid = txid
        self.idx = idx

class TransactionInput(BaseTransactionInput):
    def __init__(self, txid, idx: np.int32,  publicKey, signature = None):
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

    @staticmethod
    def from_json(input_json):
        txid = input_json['txid']
        idx = input_json['idx']
        publicKey = input_json['publicKey']
        signature = input_json['signature']
        return TransactionInput(txid, idx, publicKey, signature)

class BaseTransactionOutput:
    def __init__(self, amount):
        self.amount = amount

class TransactionOutput(BaseTransactionOutput):
    def __init__(self, amount: float, recvAddress: str, script_type = 'P2PKH'):
        super().__init__(amount)
        self.recvAddress = recvAddress
        self.script_type = script_type

    
    def toJSON(self):
        return {
            'amount': self.amount,
            'recvAddress': self.recvAddress,
            'script_type': self.script_type
        }
    
    # def getHash(self):
    #     return hashlib.sha256(self.toString().encode()).hexdigest()

    @staticmethod
    def from_json(output_json):
        amount = output_json['amount']
        recvAddress = output_json['recvAddress']
        script_type = output_json['script_type']
        return TransactionOutput(amount, recvAddress, script_type)


class Transaction:
    def __init__(self, inputList: list, outputList: list, timeStampt: float):
        self.inputList = inputList
        self.outputList = outputList

        self.time = timeStampt
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