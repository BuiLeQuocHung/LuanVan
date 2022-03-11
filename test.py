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
        print(len(temp))
        print(temp[:80])
        block = Block.from_binary(temp)

    # return Block.from_json(block_json)
    return block

print(sys.getsizeof(json.dumps(getblock(5).toJSON())))