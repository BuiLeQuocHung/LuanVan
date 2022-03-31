import pymongo

myclient = pymongo.MongoClient("mongodb://localhost:27017/")
mydb = myclient['Blockchain']
BlockColl = mydb['Block']



import firebase_admin
from firebase_admin import credentials
from firebase_admin import db

# Fetch the service account key JSON file contents
cred = credentials.Certificate('crypto-pay-2-firebase-adminsdk-pbyw2-417af6de2b.json')
# Initialize the app with a service account, granting admin privileges
firebase_admin.initialize_app(cred, {
    'databaseURL': "https://crypto-pay-2-default-rtdb.firebaseio.com/"
})
