import pymongo

myclient = pymongo.MongoClient("mongodb://localhost:27017/")
mydb = myclient['Blockchain']

# print(mydb.list_collection_names())

# TransColl = mydb['Transaction']
# ChainstateColl = mydb['Chainstate']
BlockColl = mydb['Block']

# result = TransColl.find_one({"_id": 2341})
# print( result )
# print(result['blockheight'])


