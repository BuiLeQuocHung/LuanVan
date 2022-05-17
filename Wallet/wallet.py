import random
import socket, ed25519, binascii, base58, time as time_, os, pyperclip, json, aes_cipher
from config import *
from Structure.Block import *
from datetime import datetime


import PySimpleGUI as sg
from py_crypto_hd_wallet import HdWalletBip44Coins, HdWalletBipWordsNum, HdWalletBipLanguages,\
 HdWalletBipFactory, HdWalletBipDataTypes, HdWalletBipKeyTypes, HdWalletBipChanges


from hdwallet import  utils
# from hdwallet.utils import generate_entropy
# from hdwallet.symbols import BTC as SYMBOL


wallet_path = os.path.join(root_path, 'wallets')


ClientSocket = socket.socket()
host = '192.168.1.14'
port = 50000

current_wallet = None
unused_address_idx = 0
address_balance_list = None

print('Waiting for connection')
try:
    ClientSocket.connect((host, port))
except socket.error as e:
    print(str(e))


def create_P2PKH_output_window():
    output_layout = [
        [sg.Text('Receiver address', size=20), sg.Input(key='receiver-address')],
        [sg.Text('Amount', size=20), sg.Input(key='amount')],
        [sg.Button('Add', key='add')]
    ]

    create_output_window = sg.Window('Wallet', output_layout, modal=True)

    while True:
        event, values = create_output_window.read()
        # print(event, values) #debug
        if event in (None, 'Exit', 'Cancel'):
            create_output_window.close()
            return None

        elif event == 'add':
            amount = int(values['amount'])
            address = values['receiver-address']
            if amount > 0 and validateAddress(address):
                create_output_window.close()
                return [address, amount, ScriptType.P2PKH]
    
def create_P2MS_output_window():
    output_layout = [
        [sg.Text('Multisig cript', size=20), sg.Input(key='-MULTISIG-SCRIPT-')],
        [sg.Text('Amount', size=20), sg.Input(key='amount')],
        [sg.Button('Add', key='add')]
    ]

    create_output_window = sg.Window('Wallet', output_layout, modal=True)

    while True:
        event, values = create_output_window.read()
        # print(event, values) #debug
        if event in (None, 'Exit', 'Cancel'):
            create_output_window.close()
            return None

        elif event == 'add':
            amount = int(values['amount'])
            address = values['-MULTISIG-SCRIPT-']
            if amount > 0:
                break
    create_output_window.close()
    return [address, amount, ScriptType.P2MS]

def get_addr_UTXO(address) -> list:
    data = transmitData('getaddressUTXO', [address])
    ClientSocket.sendall(data.encode())
    result =  json.loads(ClientSocket.recv(1048576).decode())
    return result

def get_balance(address):
    list_UTXOs = get_addr_UTXO(address)
    balance = 0
    for each in list_UTXOs:
        balance += each['amount']
    return balance

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

def submitTransaction(tran: Transaction):
    print(tran.toJSONwithSignature())
    data = transmitData('submittransaction', [tran.toJSONwithSignature()])
    ClientSocket.sendall(data.encode())

def validateAmountSpend(amount, fee, balance):
    if amount + fee > balance:
        sg.popup('Insufficent balance')
        return False

    return True

def createTransaction(fee, outputList: list ):
    # outputList : [[address, amount], ...]
    totalOutputAmount = 0
    for each in outputList:
        totalOutputAmount += each[1] # [address, amount, script_type]
    
    outputList = list(map(lambda x: TransactionOutput(x[1], x[0], x[2]), outputList))

    inputList = []
    totalInputAmount = 0

    used_list = []
    
    count = -1
    for key, value in current_wallet.GetData(HdWalletBipDataTypes.ADDRESS).ToDict().items():
        count += 1
        privkey = value['raw_priv']
        pubkey = value['raw_compr_pub'][2:]
        address = pubkey_to_address(pubkey)

        address_UTXOs_info = get_addr_UTXO(address)
        # print('address: ', address)
        # print('address UTXO info: ', address_UTXOs_info)

        if address_UTXOs_info:
            used_list.append(count)
        
        for UTXO_info in address_UTXOs_info:
            txid, idx = UTXO_info['_id'][:64], int(UTXO_info['_id'][64:])
            inputAmount = UTXO_info['amount']

            newInput = TransactionInput(txid, idx, pubkey)
            inputList.append(newInput)

            totalInputAmount += inputAmount

            if totalInputAmount > totalOutputAmount + fee:
                break
        
        if totalInputAmount > totalOutputAmount + fee:
            break

    # print(fee)
    # print(totalInputAmount, totalOutputAmount)

    change = totalInputAmount - totalOutputAmount - fee

    if change > 0:
        addrs_dict = current_wallet.GetData(HdWalletBipDataTypes.ADDRESS).ToDict()

        for idx, each in enumerate(filter_address('all', address_balance_list)):
            if each[0] == 'unused' and idx not in used_list:
                random_number = idx
                break

        addr_dict = addrs_dict['address_{}'.format(random_number)]
        change_output = TransactionOutput(change, pubkey_to_address(addr_dict['raw_compr_pub'][2:]))
        outputList.append(change_output)

    # print(inputList)
    # print(outputList[0].toJSON())
    
    transaction = Transaction( inputList, outputList, int(time_.time()))
    return transaction

def sign_transaction(transaction: Transaction):    
    for input in transaction.inputList:
        private_key = get_correspond_privatekey(input.publicKey)
        privkeyObject = ed25519.SigningKey(binascii.unhexlify(private_key.encode()))
        input.signature = privkeyObject.sign(binascii.unhexlify(transaction.hash.encode())).hex()
    
    return transaction

def get_correspond_privatekey(public_key: str):
    for key, value in current_wallet.GetData(HdWalletBipDataTypes.ADDRESS).ToDict().items():
        if value['raw_compr_pub'][2:] == public_key:
            # print('corrspond private key: ', value['raw_priv'])
            return value['raw_priv']

def wallet_window():
    global current_wallet
    wallet_layout = [
        [sg.Button('Create Wallet', key="-CREATE-WALLET-"), sg.Input(key='-WALLET-NAME-')],
        [sg.Button('Open Wallet', key="-OPEN-WALLET-"), sg.Input(key='-WALLET-PATH-', readonly=True), sg.FileBrowse(initial_folder= wallet_path , target='-WALLET-PATH-', key="-BROWSE-")]
    ]

    result = ""

    window = sg.Window("LV-Wallet", wallet_layout)
    while True:
        event, values = window.read()
        # print(event, values) #debug
        if event in (None, 'Exit', 'Cancel'):
            result = "close"
            break

        elif event == "-OPEN-WALLET-":
            if values['-WALLET-PATH-'] != '':
                while True:
                    password = password_window()
                    if not password:
                        break
                    
                    try:
                        current_wallet = load_wallet(values['-WALLET-PATH-'], password)
                        result = "open wallet"
                        window.close()
                        return result
                    except:
                        pass


        elif event == "-CREATE-WALLET-":
            temp =  list(os.walk('wallets'))
            print(temp)
            if temp != []:
                _, _, filenames = temp[0]
            else:
                filenames = []

            print(filenames)
            if values['-WALLET-NAME-'] != '' and '{}.txt'.format(values['-WALLET-NAME-']) not in filenames:
                type_of_wallet(values['-WALLET-NAME-'])
                result = "new wallet"
                break
    
    window.close()
    return result

def password_window():
    password_layout = [
        [sg.Text('Password'), sg.Input('', key= '-PASSWORD-', password_char='*', expand_x=True)],
        [sg.Button('Next', key="-NEXT-")]
    ]

    window = sg.Window('Encrypt Wallet', password_layout)

    while True:
        event, values = window.read()
        if event in (None, 'Exit', 'Cancel'):
            window.close()
            return None

        elif event == '-NEXT-':
            break
    
    window.close()
    return values['-PASSWORD-']

def create_new_wallet(wallet_name: str):
    acc_idx = 0
    addr_num = 30
    addr_offset = 0

    hd_wallet_fact = HdWalletBipFactory(HdWalletBip44Coins.POLKADOT_ED25519_SLIP)
    hd_wallet = hd_wallet_fact.CreateRandom(wallet_name, HdWalletBipWordsNum.WORDS_NUM_12)
    hd_wallet.Generate(acc_idx=acc_idx, change_idx=HdWalletBipChanges.CHAIN_EXT, addr_num=addr_num, addr_off=addr_offset)

    mnemonic = hd_wallet.GetData(HdWalletBipDataTypes.MNEMONIC)
    derivation = "m'/44'/354'"

    # global current_wallet

    # STRENGTH: int = 128  
    # LANGUAGE: str = "english" 
    # ENTROPY: str = generate_entropy(strength=STRENGTH)
    # PASSPHRASE: str = None

    # master_hdwallet: HDWallet = HDWallet("BTC", use_default_path=False)
    # master_hdwallet.from_entropy(
    #     entropy=ENTROPY, language=LANGUAGE, passphrase=PASSPHRASE
    # )

    # mnemonic = master_hdwallet.mnemonic()

    # derivation = "m/0'"
    # addresses = []
    # for i in range(10):
    #     new_addr = generate_address(master_hdwallet, derivation + f"/{i}'")
    #     addresses.append(new_addr)
    # data = {
    #     'addresses': addresses,
    #     'keystore': {
    #         'derivation': derivation,
    #         'mnemonic': mnemonic
    #     }
    # }

    data = {
        'mnemonic': mnemonic,
    }

    global current_wallet
    current_wallet = hd_wallet

    return data

def address_is_used(address):
    data = transmitData('addressexist', [address])
    ClientSocket.sendall(data.encode())
    result = json.loads(ClientSocket.recv(1048576).decode())

    if result == '1':
        return True
    else:
        return False

def number_of_addr_to_gen(wallet_name: str, mnemonic: str):

    acc_idx = 0
    addr_num = 200
    addr_offset = 0

    hd_wallet_fact = HdWalletBipFactory(HdWalletBip44Coins.POLKADOT_ED25519_SLIP)
    hd_wallet = hd_wallet_fact.CreateFromMnemonic(wallet_name, mnemonic)
    hd_wallet.Generate(acc_idx=acc_idx, change_idx=HdWalletBipChanges.CHAIN_EXT, addr_num=addr_num, addr_off=addr_offset)

    idx = -1
    count = 0
    for key, value in hd_wallet.GetData(HdWalletBipDataTypes.ADDRESS).ToDict().items():
        idx += 1

        privkey = value['raw_priv']
        pubkey = value['raw_compr_pub'][2:]
        address = pubkey_to_address(pubkey)

        if not address_is_used(address):
            count += 1
        else:
            count = 0
        if count == 20:
            return idx

def encrypted_wallet(password, data):

    data_encrypter = aes_cipher.DataEncrypter()
    content = json.dumps(data)
    data_encrypter.Encrypt(content, password, itr_num= 10)
    enc_data = data_encrypter.GetEncryptedData().hex()
    
    return enc_data
    


def create_wallet_from_menemonic(wallet_name: str, mnemonic: str):
    acc_idx = 0
    addr_num = number_of_addr_to_gen(wallet_name, mnemonic)
    addr_offset = 0

    hd_wallet_fact = HdWalletBipFactory(HdWalletBip44Coins.POLKADOT_ED25519_SLIP)
    hd_wallet = hd_wallet_fact.CreateFromMnemonic(wallet_name, mnemonic)
    hd_wallet.Generate(acc_idx=acc_idx, change_idx=HdWalletBipChanges.CHAIN_EXT, addr_num=addr_num, addr_off=addr_offset)

    mnemonic = hd_wallet.GetData(HdWalletBipDataTypes.MNEMONIC)
    derivation = "m'/44'/354'"

    data = {
        'mnemonic': mnemonic,
    }

    # global current_wallet

    # master_hdwallet = HDWallet("BTC")
    # master_hdwallet.from_mnemonic(mnemonic, language= "english", passphrase=None)

    # derivation = "m/0'"
    # addresses = []
    # for i in range(10):
    #     new_addr = generate_address(master_hdwallet, derivation + f"/{i}'")
    #     addresses.append(new_addr)

    # data = {
    #     'addresses': addresses,
    #     'keystore': {
    #         'derivation': derivation,
    #         'mnemonic': mnemonic
    #     }
    # }

    global current_wallet
    current_wallet = hd_wallet

    return data

def type_of_wallet(wallet_name: str):
    wallet_type = None
    wallet_type_layout = [
        [sg.Radio('Create a new menemonic seed', 'wallet_type', default=True, key="-NEW-WALLET-")],
        [sg.Radio('I already have a menemonic seed', 'wallet_type', key="-FROM-MNEMONIC-")],
        [sg.Button('Next', key="-NEXT-")]
    ]

    window = sg.Window("LV-Wallet", wallet_type_layout)
    while True:
        event, values = window.read()
        # print(event, values) #debug
        if event in (None, 'Exit', 'Cancel'):
            break
        elif event =='-NEXT-':
            wallet_type = "-NEW-WALLET-" if values["-NEW-WALLET-"] else "-FROM-MNEMONIC-"
            if wallet_type == "-NEW-WALLET-":
                data = create_new_wallet(wallet_name)
                display_seed_window(current_wallet.GetData(HdWalletBipDataTypes.MNEMONIC))
                
                password =  password_window()
                while not password:
                    password =  password_window()

                enc_data = encrypted_wallet(password, data)

                save_wallet(wallet_name, enc_data)
                break
                

            elif wallet_type == "-FROM-MNEMONIC-":
                mnemonic = input_seed_window()
                if utils.is_mnemonic(mnemonic):
                    data = create_wallet_from_menemonic(wallet_name, mnemonic)
                    password =  password_window()
                    while not password:
                        password =  password_window()

                    enc_data = encrypted_wallet(password, data)
                    save_wallet(wallet_name, enc_data)
                    break

def save_wallet(wallet_name: str, data):
    with open(wallet_path + f'/{wallet_name}.txt', "w+") as file:
        file.write(data)

def load_wallet(wallet_path: str, password):
    data_decrypter = aes_cipher.DataDecrypter()
    wallet_name = wallet_path.split('/')[-1].split('.')[0]
    with open(wallet_path, "r+") as file:
        content = binascii.unhexlify(file.read().encode())
        data_decrypter.Decrypt(content, password, itr_num= 10)
        dec_data = data_decrypter.GetDecryptedData()

    data = json.loads(dec_data.decode())

    addr_num = number_of_addr_to_gen(wallet_name, data['mnemonic'])

    hd_wallet_fact = HdWalletBipFactory(HdWalletBip44Coins.POLKADOT_ED25519_SLIP)
    hd_wallet = hd_wallet_fact.CreateFromMnemonic(wallet_name, data['mnemonic'])
    hd_wallet.Generate(acc_idx=0, change_idx=HdWalletBipChanges.CHAIN_EXT, addr_num=addr_num, addr_off=0)
    
    global current_wallet
    current_wallet = hd_wallet
    return current_wallet

# def generate_hd_wallet(mnemonic: str):
#     hdwallet = HDWallet("BTC")
#     hdwallet.from_mnemonic(mnemonic, language= 'english')

#     return hdwallet

# def generate_private_key(master_hdwallet: HDWallet, path: str):
#     private_key = master_hdwallet.from_path(path).private_key()
#     master_hdwallet.clean_derivation()
#     return private_key

# def generate_compress_publickey(master_hdwallet: HDWallet, path: str) -> str:   
#     public_key = master_hdwallet.from_path(path).public_key()
#     master_hdwallet.clean_derivation()
#     return public_key


# def generate_address(master_hdwallet: HDWallet, path: str):
#     address = master_hdwallet.from_path(path).p2pkh_address()
#     master_hdwallet.clean_derivation()
#     return address


def display_seed_window(mnemonic: str):
    display_seed_layout = [
        [sg.Text('Mnemonic')],
        [sg.Multiline(mnemonic, size=(30, 5))]
    ]

    window = sg.Window('LVWallet', display_seed_layout)
    while True:
        event, values = window.read()
        print(event, values) #debug
        if event in (None, 'Exit', 'Cancel'):
            break

def input_seed_window() -> str:
    input_seed_layout = [
        [sg.Text('Input your mnemonic seed')],
        [sg.Multiline('', size=(30, 5), key="-IN-")],
        [sg.Button("Next", key="-NEXT-")]
    ]

    window = sg.Window('LVWallet', input_seed_layout)
    while True:
        event, values = window.read()
        print(event, values) #debug
        if event in (None, 'Exit', 'Cancel'):
            break

        elif event == '-NEXT-':
            if utils.is_mnemonic(values['-IN-']):
                mnemonic = values['-IN-']            
                break
    
    window.close()
    return mnemonic

def update_address_balance():
    addrs_dict = current_wallet.GetData(HdWalletBipDataTypes.ADDRESS).ToDict()
    list_address = [ pubkey_to_address(addrs_dict[each]['raw_compr_pub'][2:]) for each in addrs_dict]
    wallet_balance = 0

    result = []
    for idx, address in enumerate(list_address):
        amount = get_balance(address)
        wallet_balance += amount

        if address_is_used(address):
            typ = 'used'
        else:
            typ = 'unused'

        result.append( [typ, address, amount] )
    
    return result, wallet_balance

def get_wallet_trans_history():
    addrs_dict = current_wallet.GetData(HdWalletBipDataTypes.ADDRESS).ToDict()
    list_address = [ pubkey_to_address(addrs_dict[each]['raw_compr_pub'][2:]) for each in addrs_dict]

    data = transmitData('getaddressTransactions', [list_address])

    ClientSocket.sendall(data.encode())
    result = json.loads(ClientSocket.recv(1048675).decode())
    
    return result #list trans_json no signature

def trans_history_summary_info(list_trans_json):
    result = []
    addrs_dict = current_wallet.GetData(HdWalletBipDataTypes.ADDRESS).ToDict()
    list_address = [ pubkey_to_address(addrs_dict[each]['raw_compr_pub'][2:]) for each in addrs_dict]

    for trans_json in list_trans_json:
        trans = Transaction.from_json(trans_json)
        send_amount = 0
        for trans_output in trans.outputList:
            if trans_output.recvAddress not in list_address:
                send_amount += trans_output.amount

        trans_date = datetime.fromtimestamp(trans.time)
        result.append( [trans_date, trans.hash, send_amount] )
    
    result.sort(key= lambda x: x[0], reverse= True)
    for each in result:
        each[0] = each[0].strftime('%d-%m-%y')

    return result

def wallet_info_window():
    wallet_name = current_wallet.GetData(HdWalletBipDataTypes.WALLET_NAME)
    mnemonic = current_wallet.GetData(HdWalletBipDataTypes.MNEMONIC)

    wallet_info_layout = [
        [sg.Text('Wallet name:', size=(20,)), sg.Text(wallet_name)],
        [sg.Text('Script type:', size=(20,)), sg.Text('P2PKH')],
        [sg.Text('Mnemonic')],
        [sg.Multiline(mnemonic, size=(30, 5), expand_x=True)]
    ]

    window = sg.Window("LVWallet", wallet_info_layout)

    while True:
        event, values = window.read()
        if event in (None, 'Exit', 'Cancel'):
            break
    
    window.close()

def get_trans_output(trans_hash, idx):
    data = transmitData('getTransOutput', [trans_hash, idx])
    ClientSocket.sendall(data.encode())
    trans_output_json = json.loads(ClientSocket.recv(1048576).decode())
    return TransactionOutput.from_json(trans_output_json)

def get_trans_info(trans_hash):
    data = transmitData('getTransInfo', [trans_hash])
    ClientSocket.sendall(data.encode())
    trans_info_json = json.loads(ClientSocket.recv(1048576).decode())
    return trans_info_json

def get_output_amount(trans: Transaction):
    amount = 0
    for output in trans.outputList:
        if output.recvAddress not in addr_list():
            amount += output.amount
    
    return amount

def addr_list():
    addrs_dict = current_wallet.GetData(HdWalletBipDataTypes.ADDRESS).ToDict()
    list_address = [ pubkey_to_address(addrs_dict[each]['raw_compr_pub'][2:]) for each in addrs_dict]
    return list_address

def show_signed_transaction(trans: Transaction):
    amount_sent = 0
    fee = 0

    outputAmount = 0
    for output in trans.outputList:
        print(output.amount)
        if output.recvAddress not in addr_list():
            amount_sent += output.amount
        outputAmount += output.amount

    
    inputAmount = 0
    for each in trans.inputList:
        trans_output = get_trans_output(each.txid, each.idx)
        inputAmount += trans_output.amount
    
    fee = inputAmount - outputAmount
    
    is_sign = False
    for each in trans.inputList:
        if each.signature == None:
            is_sign = False
            break
        else:
            is_sign = True

    

    status_text = 'Signed' if is_sign else  'Unsigned'

    # for each in trans.inputList:
    #     print(each.toJSON())

    return_result = None

    inputs = [[each.txid, each.idx] for each in trans.inputList]
    outputs = [[each.recvAddress, each.amount] for each in trans.outputList]

    trans_detail_layout = [
        [sg.Text('Txid: {}'.format(trans.hash))],
        [sg.Text('Status: {}'.format(status_text), key= '-STATUS-')],
        [sg.Text('Fee: {}'.format(fee))],
        [sg.Text('Sent Amount: {}'.format(amount_sent))],

        [sg.Text('Input')],
        [sg.Table(inputs, ['txid', 'idx'],  max_col_width=55,
                    auto_size_columns=True, justification='left', 
                    num_rows=5, key="-TRANS-INPUTS-TABLE-",
                    expand_x=True)],

        [sg.Text('Output')],
        [sg.Table(outputs, ['receiver', 'amount'],  max_col_width=55,
                    auto_size_columns=True, justification='left', 
                    num_rows=5, key="-TRANS-OUTPUTS-TABLE-",
                    expand_x=True)],
        
        [sg.Button('Sign', key='-SIGN-'), sg.Button('Send', key='-SEND-')]
    ]

    window = sg.Window('Transaction', trans_detail_layout)

    sign_trans = None

    while True:
        event, values = window.read()
        print(event, values)
        if event in (None, 'Exit', 'Cancel'):
            return_result = 'Close'
            break
        
        elif event == '-SIGN-':
            if not is_sign:
                trans = sign_transaction(trans)
                is_sign = True
                window["-STATUS-"].update('Status: Signed')
        
        elif event == '-SEND-':
            if is_sign:
                submitTransaction(trans)
                return_result = 'Sent'
                break
        
        
    
    window.close()
    return return_result

def show_trans_detail(trans_hash):
    trans_info_json = get_trans_info(trans_hash)
    trans = Transaction.from_json(trans_info_json)
    
    confirmation = trans_info_json['confirmation']
    if confirmation == -1:
        confirmation = 'mempool'

    inputAmount = trans_info_json['inputAmount']
    outputAmount = get_output_amount(trans)

    inputs = [[each.txid, each.idx] for each in trans.inputList]
    outputs = [[each.recvAddress, each.amount] for each in trans.outputList]

    trans_detail_layout = [
        [sg.Text('Txid: {}'.format(trans_hash))],
        [sg.Text('Fee: {}'.format(inputAmount - outputAmount))],
        [sg.Text('Confirmation: {}'.format(confirmation))],
        [sg.Text('Sent Amount: {}'.format(outputAmount))],

        [sg.Text('Input')],
        [sg.Table(inputs, ['txid', 'idx'],  max_col_width=55,
                    auto_size_columns=True, justification='left', 
                    num_rows=5, key="-TRANS-INPUTS-TABLE-",
                    expand_x=True)],

        [sg.Text('Output')],
        [sg.Table(outputs, ['receiver', 'amount'],  max_col_width=55,
                    auto_size_columns=True, justification='left', 
                    num_rows=5, key="-TRANS-OUTPUTS-TABLE-",
                    expand_x=True)]
    ]

    window = sg.Window('Transaction', trans_detail_layout)
    while True:
        event, values = window.read()
        print(event, values) #debug
        if event in (None, 'Exit', 'Cancel'):
            break

def gettotalOutputAmount(outputList):
    amount = 0
    for each in outputList:
        amount += each[1]
    return amount

def filter_address(address_type, address_balance_list):
    used_list = [] # address_balance_list[0: unused_address_idx]
    unused_list = [] # address_balance_list[unused_address_idx:]

    for each in address_balance_list:
        if each[0] == 'used':
            used_list.append(each)
        else:
            unused_list.append(each)

    if address_type == 'all':
        return address_balance_list
    elif address_type == 'used':
        return used_list
    elif address_type == 'unused':
        return unused_list

def refresh_wallet():
    global current_wallet
    mnemonic = current_wallet.GetData(HdWalletBipDataTypes.MNEMONIC)
    wallet_name = current_wallet.GetData(HdWalletBipDataTypes.WALLET_NAME)

    acc_idx = 0
    addr_num = number_of_addr_to_gen(wallet_name, mnemonic)
    addr_offset = 0

    hd_wallet_fact = HdWalletBipFactory(HdWalletBip44Coins.POLKADOT_ED25519_SLIP)
    hd_wallet = hd_wallet_fact.CreateFromMnemonic(wallet_name, mnemonic)
    hd_wallet.Generate(acc_idx=acc_idx, change_idx=HdWalletBipChanges.CHAIN_EXT, addr_num=addr_num, addr_off=addr_offset)
    
    current_wallet = hd_wallet

def main_window():
    global address_balance_list, list_output
    list_output = []
    address_balance_list, wallet_balance = update_address_balance()

    global list_trans_json
    list_trans_json = get_wallet_trans_history()
    history_info = trans_history_summary_info(list_trans_json)

    menu_def = [['File', ['Recently Open', 'Open', 'New','Close']] , ['Wallet',['Infomation']]]

    sign_trans = None
    is_sign = False

    history_layout = [
        [sg.Table(history_info, headings=['date', 'txid', 'send amount'], max_col_width=55,
                    auto_size_columns=True, justification='left', 
                    num_rows=5, key="-HISTORY-TABLE-",
                    expand_x=True, expand_y=True,
                    right_click_menu=['Right', ['Details']],
                    right_click_selects=True
        )],
        [sg.Button('Refresh', key='-REFRESH-HISTORY-TABLE-')]
    ]

    address_layout = [
        [sg.Combo(['all', 'unused', 'used'], default_value='all', size=(20, 6), key="-ADDRESS-TYPE-", enable_events=True)],
        [sg.Table(address_balance_list, headings=['type', 'address', 'balance'], max_col_width=35,
                    auto_size_columns=True, justification='left', 
                    num_rows=5, key="-ADDRESS-TABLE-",
                    expand_x=True, expand_y=True,
                    
        )],
        [sg.Button('Refresh', key='-REFRESH-ADDR-TABLE-')]
    ]

    send_layout = [
        [sg.Text('Fee'), sg.Input('0', key='-FEE-', expand_x=True)],
        [sg.Table([], headings=['script', 'amount'], max_col_width=35,
                    auto_size_columns=True, justification='left', 
                    num_rows=5, key="-OUTPUT-TABLE-",
                    expand_x=True, 
                    select_mode= sg.SELECT_MODE_BROWSE,
                    enable_events=True,
                    right_click_menu= ['Right', ['Delete']],
                    right_click_selects=True,
        )],
        [sg.Button('P2PKH output', key='-P2PKH-OUTPUT-'), sg.Button('P2MS output', key='-P2MS-OUTPUT-'), sg.Button('Clear', key='-CLEAR-')],
        [sg.Button('Open', key='-OPEN-TRANSACTION-')],
    ]

    main_layout = [
        [sg.Menu(menu_def)],
        [sg.TabGroup([
            [sg.Tab("Address", address_layout)],
            [sg.Tab("Send", send_layout)],
            [sg.Tab("History", history_layout)]
        ], tab_background_color='grey', selected_background_color='white', selected_title_color='black')],
        [sg.Text('Balance'), sg.Input(wallet_balance, readonly=True, key='-WALLET-BALANCE-')]
    ]

    window = sg.Window("LVWallet", main_layout, finalize=True)
    window.bind("<Control-c>", "Control-C")
    window.bind("<Control-C>", "Control-C")

    while True:
        event, values = window.read(timeout= 5000)
        # print(event, values) #debug
        if event in (None, 'Exit', 'Cancel'):
            break
            
        elif event == '-ADDRESS-TYPE-':
            window["-ADDRESS-TABLE-"].update(filter_address(values['-ADDRESS-TYPE-'], address_balance_list))
        
        elif event == '-P2PKH-OUTPUT-':
            output = create_P2PKH_output_window()
            if output:
                list_output.append(output)
                window["-OUTPUT-TABLE-"].update(list_output)

        elif event == '-P2MS-OUTPUT-':
            output = create_P2MS_output_window()
            if output:
                list_output.append(output)
                window["-OUTPUT-TABLE-"].update(list_output)
        
        elif event == '-OPEN-TRANSACTION-':
            fee = int(values['-FEE-'])
            if validateAmountSpend(gettotalOutputAmount(list_output), fee, int(values['-WALLET-BALANCE-'])):

                sign_trans = createTransaction(fee, list_output)
                
                result = show_signed_transaction(sign_trans)

                if result == 'Sent':
                    window['-FEE-'].update('0')
                    list_output = []
                    window['-OUTPUT-TABLE-'].update(list_output)

                    sign_trans = None
                    is_sign = False

        # elif event == '-SUBMIT-TRANSACTION-':
        #     if sign_trans:
        #         submitTransaction(sign_trans)

        #     window['-FEE-'].update('')
        #     list_output = []
        #     window['-OUTPUT-TABLE-'].update(list_output)

        #     sign_trans = None
        #     is_sign = False

            # address_balance_list, wallet_balance = update_address_balance()
            # window["-ADDRESS-TABLE-"].update(address_balance_list)
            # window['-WALLET-BALANCE-'].update(wallet_balance)
        
        elif event == 'Control-C' and values["-ADDRESS-TABLE-"]:
            row = int( values["-ADDRESS-TABLE-"][0])
            address = filter_address(values['-ADDRESS-TYPE-'], address_balance_list)[row][1] #get address
            pyperclip.copy(address)

        elif event == "Infomation":
            wallet_info_window()
        
        elif event == '-REFRESH-ADDR-TABLE-':
            address_balance_list, wallet_balance = update_address_balance()
            window["-ADDRESS-TABLE-"].update(filter_address(values['-ADDRESS-TYPE-'], address_balance_list))
            window['-WALLET-BALANCE-'].update(wallet_balance)

        elif event == '-REFRESH-HISTORY-TABLE-':
            list_trans_json = get_wallet_trans_history()
            history_info = trans_history_summary_info(list_trans_json)
            window['-HISTORY-TABLE-'].update(history_info)
        
        elif event == 'Details':
            row = int( values["-HISTORY-TABLE-"][0])
            trans_hash = history_info[row][1]
            print('row: ', row, 'trans_hash: ', trans_hash)
            show_trans_detail(trans_hash)

        elif event == 'Delete':
            row = int( values["-OUTPUT-TABLE-"][0])
            list_output.pop(row)
            window['-OUTPUT-TABLE-'].update(list_output)

        elif event == '-CLEAR-':
            list_output = []
            window['-OUTPUT-TABLE-'].update(list_output)

            window['-FEE-'].update('0')
            sign_trans = None
            is_sign = False


        address_balance_list, wallet_balance = update_address_balance()
        window["-ADDRESS-TABLE-"].update(filter_address(values['-ADDRESS-TYPE-'], address_balance_list))
        window['-WALLET-BALANCE-'].update(wallet_balance)

        list_trans_json = get_wallet_trans_history()
        history_info = trans_history_summary_info(list_trans_json)
        window['-HISTORY-TABLE-'].update(history_info)

        refresh_wallet()


def main():
    result = wallet_window()
    if result == "close": return
    main_window()

if __name__ == '__main__':
    main()





ClientSocket.close()