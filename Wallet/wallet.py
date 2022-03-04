import socket, ecdsa, binascii, base58, time, os, pyperclip, json
from config import *
from Structure.Block import *
from bitcoin import *
from functools import reduce

import PySimpleGUI as sg
from hdwallet import HDWallet, utils
from hdwallet.utils import generate_entropy
from hdwallet.symbols import BTC as SYMBOL



wallet_path = os.path.join(root_path, 'wallets')


ClientSocket = socket.socket()
host = '192.168.11.115'
port = 12345

current_wallet = {}

print('Waiting for connection')
try:
    ClientSocket.connect((host, port))
except socket.error as e:
    print(str(e))

# private_key = "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725"
# public_key = "0450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b23522cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6"
# compressed_public_key = "0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"
# address = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"
# pubkeyScript = "OP_DUP OP_HASH {} OP_EQUALVERIFY OP_CHECKSIG".format(address)

# private_key = "8EA7C27775BAADEE8CC4F0671C431D0399A4BD5D5F52BC15708AD4EDBD456EEF"
# public_key = "04A5B3B2DB2EB52C6481B791F7ABDED1A85F29810A3BB93C0E58AC36595C690BF7ADF9472E4A9AB86148427CB44A564618BEE2209890BB4269A3E9738F8F571CCD"
# compressed_public_key = "03a5b3b2db2eb52c6481b791f7abded1a85f29810a3bb93c0e58ac36595c690bf7"
# address = "1Ap4JgMR3pCvNfFZ6z6FMoq9zprSSWPZfQ"
# pubkeyScript = "OP_DUP OP_HASH {} OP_EQUALVERIFY OP_CHECKSIG".format(address)



def create_output_window():
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
            return None

        elif event == 'add':
            amount = int(values['amount'])
            address = values['receiver-address']
            if amount > 0 and validateAddress(address):
                create_output_window.close()
                return [address, amount]
    
    


def get_addr_UTXO(address) -> list:
    data = transmitData('getaddressUTXO', [address])
    ClientSocket.send(data.encode())
    result =  json.loads(ClientSocket.recv(65536).decode()) # list of record
    print(sys.getsizeof(result))
    return result

def get_balance(address):
    list_UTXOs = get_addr_UTXO(address)
    balance = 0
    for each in list_UTXOs:
        balance += each['amount']
    return balance

def validateAddress(address):
    base58Decoder = base58.b58decode(address).hex()

    prefixAndHash = base58Decoder[:len(base58Decoder)-8]
    checksum = base58Decoder[len(base58Decoder)-8:]

    hash = prefixAndHash
    for x in range(1,3):
        hash = hashlib.sha256(binascii.unhexlify(hash)).hexdigest()

    if(checksum == hash[:8]):
        return True
    else:
        return False

def submitTransaction(tran: Transaction):
    print(tran.toJSONwithSignature())
    data = transmitData('submittransaction', [tran.toJSONwithSignature()])
    ClientSocket.send(data.encode())

def validateAmountSpend(amount, fee, balance):
    if amount + fee > balance:
        sg.popup('Insufficent balance')
        return False

    return True

def createTransaction(fee, outputList: list ):
    # outputList : [[address, amount], ...]
    totalOutputAmount = 0
    for each in outputList:
        totalOutputAmount += each[1] # [address, amount]
    
    outputList = list(map(lambda x: TransactionOutput(x[1], x[0]), outputList))

    master_hdwallet = generate_hd_wallet(current_wallet['data']['keystore']['mnemonic'])
    derivation = current_wallet['data']['keystore']['derivation']

    inputList = []
    totalInputAmount = 0
    
    for address_idx, address in enumerate(current_wallet['data']['addresses']):
        address_UTXOs_info = get_addr_UTXO(address)
        related_compress_publickey = generate_compress_publickey(master_hdwallet, derivation + f"/{address_idx}'")
        
        for UTXO_info in address_UTXOs_info:
            txid, idx = UTXO_info['_id'][:64], int(UTXO_info['_id'][64:])
            inputAmount = UTXO_info['amount']

            newInput = TransactionInput(txid, idx, related_compress_publickey)
            inputList.append(newInput)

            totalInputAmount += inputAmount

            if totalInputAmount > totalOutputAmount + fee:
                break
        
        if totalInputAmount > totalOutputAmount + fee:
            break
    change = totalInputAmount - totalOutputAmount - fee
    if change > 0:
        change_output = TransactionOutput(change, current_wallet['data']['addresses'][random.randint(0,9)])
        outputList.append(change_output)
    
    transaction = Transaction(inputList, outputList, time.time())

    return transaction

def sign_transaction(transaction: Transaction):    
    for input in transaction.inputList:
        private_key = get_correspond_privatekey(input.publicKey)
        privkeyObject = ecdsa.SigningKey.from_string(binascii.unhexlify(private_key.encode()), curve= ecdsa.SECP256k1, hashfunc=hashlib.sha256)
        input.signature = privkeyObject.sign_digest(binascii.unhexlify(transaction.hash.encode())).hex()
    
    return transaction

def get_correspond_privatekey(public_key: str):
    master_hdwallet = generate_hd_wallet(current_wallet['data']['keystore']['mnemonic'])
    derivation = current_wallet['data']['keystore']['derivation']

    for i in range(10):
        if generate_compress_publickey(master_hdwallet, derivation + f"/{i}'") == public_key:
            private_key = generate_private_key(master_hdwallet, derivation + f"/{i}'")
            return private_key

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
                current_wallet = load_wallet(values['-WALLET-PATH-'])
                result = "open wallet"
                break

        elif event == "-CREATE-WALLET-":
            _, _, filenames = list(os.walk('wallets'))[0]
            if values['-WALLET-NAME-'] != '' and '{}.txt'.format(values['-WALLET-NAME-']) not in filenames:
                type_of_wallet(values['-WALLET-NAME-'])
                result = "new wallet"
                break
    
    window.close()
    return result

def create_new_wallet(wallet_name: str):
    global current_wallet

    STRENGTH: int = 128  
    LANGUAGE: str = "english" 
    ENTROPY: str = generate_entropy(strength=STRENGTH)
    PASSPHRASE: str = None

    master_hdwallet: HDWallet = HDWallet("BTC", use_default_path=False)
    master_hdwallet.from_entropy(
        entropy=ENTROPY, language=LANGUAGE, passphrase=PASSPHRASE
    )

    mnemonic = master_hdwallet.mnemonic()

    derivation = "m/0'"
    addresses = []
    for i in range(10):
        new_addr = generate_address(master_hdwallet, derivation + f"/{i}'")
        addresses.append(new_addr)

    data = {
        'addresses': addresses,
        'keystore': {
            'derivation': derivation,
            'mnemonic': mnemonic
        }
    }
    save_wallet(wallet_name, data)
    current_wallet = {
        'name': wallet_name,
        'data': data
    }

def create_wallet_from_menemonic(wallet_name: str, mnemonic: str):
    global current_wallet

    master_hdwallet = HDWallet("BTC")
    master_hdwallet.from_mnemonic(mnemonic, language= "english", passphrase=None)

    derivation = "m/0'"
    addresses = []
    for i in range(10):
        new_addr = generate_address(master_hdwallet, derivation + f"/{i}'")
        addresses.append(new_addr)

    data = {
        'addresses': addresses,
        'keystore': {
            'derivation': derivation,
            'mnemonic': mnemonic
        }
    }
    save_wallet(wallet_name, data)
    current_wallet = {
        'name': wallet_name,
        'data': data
    }

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
        print(event, values) #debug
        if event in (None, 'Exit', 'Cancel'):
            break
        elif event =='-NEXT-':
            wallet_type = "-NEW-WALLET-" if values["-NEW-WALLET-"] else "-FROM-MNEMONIC-"
            if wallet_type == "-NEW-WALLET-":
                create_new_wallet(wallet_name)
                display_seed_window(current_wallet['data']['keystore']['mnemonic'])
            
            elif wallet_type == "-FROM-MNEMONIC-":
                mnemonic = input_seed_window()
                if utils.is_mnemonic(mnemonic):
                    create_wallet_from_menemonic(wallet_name, mnemonic)


def save_wallet(wallet_name: str, data: dict):
    with open(wallet_path + f'/{wallet_name}.txt', "w+") as file:
        json.dump(data, file, sort_keys=True, indent= 4, separators=(', ', ': '))

def load_wallet(wallet_path: str):
    wallet_name = wallet_path.split('/')[-1].split('.')[0]
    with open(wallet_path, "r+") as file:
        current_wallet = {
            'wallet_name': wallet_name,
            'data': json.load(file)
        }
    # for key in current_wallet:
    #     print(key, current_wallet[key])
    return current_wallet

def generate_hd_wallet(mnemonic: str):
    hdwallet = HDWallet("BTC")
    hdwallet.from_mnemonic(mnemonic, language= 'english')

    return hdwallet

def generate_private_key(master_hdwallet: HDWallet, path: str):
    private_key = master_hdwallet.from_path(path).private_key()
    master_hdwallet.clean_derivation()
    return private_key

def generate_compress_publickey(master_hdwallet: HDWallet, path: str) -> str:   
    public_key = master_hdwallet.from_path(path).public_key()
    master_hdwallet.clean_derivation()
    return public_key


def generate_address(master_hdwallet: HDWallet, path: str):
    address = master_hdwallet.from_path(path).p2pkh_address()
    master_hdwallet.clean_derivation()
    return address


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
    result = []
    list_address = current_wallet['data']['addresses']
    wallet_balance = 0

    for address in list_address:
        amount = get_balance(address)
        wallet_balance += amount
        result.append( [address, amount] )
    
    return result, wallet_balance

def wallet_info_window():
    wallet_name = current_wallet['wallet_name']
    mnemonic = current_wallet['data']['keystore']['mnemonic']

    wallet_info_layout = [
        [sg.Text('Wallet name:', size=(20,)), sg.Text(wallet_name)],
        [sg.Text('Script type:', size=(20,)), sg.Text('P2PKH')],
        [sg.Text('Seed standard', size=(20,)), sg.Text('Bip39')],
        [sg.Text('Mnemonic')],
        [sg.Multiline(mnemonic, size=(30, 5), expand_x=True)]
    ]

    window = sg.Window("LVWallet", wallet_info_layout)

    while True:
        event, values = window.read()
        if event in (None, 'Exit', 'Cancel'):
            break

def main_window():
    list_output = []
    address_balance_list, wallet_balance = update_address_balance()
    

    menu_def = [['File', ['Recently Open', 'Open', 'New','Close']] , ['Wallet',['Infomation']]]

    address_layout = [
        [sg.Table(address_balance_list, headings=['address', 'balance'], max_col_width=35,
                    auto_size_columns=True, justification='left', 
                    num_rows=5, key="-ADDRESS-TABLE-",
                    expand_x=True, expand_y=True
        )],
        [sg.Button('Refresh', key='-REFRESH-')]
    ]

    send_layout = [
        [sg.Text('Fee'), sg.Input('0', key='-FEE-', expand_x=True)],
        [sg.Table([], headings=['address', 'amount'], max_col_width=35,
                    auto_size_columns=True, justification='left', 
                    num_rows=5, key="-OUTPUT-TABLE-",
                    expand_x=True, 
                    select_mode= sg.SELECT_MODE_BROWSE,
                    enable_events=True
        )],
        [sg.Button('Create output', key='-CREATE-OUTPUT-'), sg.Button('Clear', key='-CLEAR-')],
        [sg.Button('Send', key='-SUBMIT-TRANSACTION-')],
    ]

    main_layout = [
        [sg.Menu(menu_def)],
        [sg.TabGroup([
            [sg.Tab("Address", address_layout)],
            [sg.Tab("Send", send_layout)]
        ], tab_background_color='grey', selected_background_color='white', selected_title_color='black')],
        [sg.Text('Balance'), sg.Input(wallet_balance, readonly=True, key='-WALLET-BALANCE-')]
    ]

    window = sg.Window("LVWallet", main_layout, finalize=True)
    window.bind("<Control-c>", "Control-C")
    window.bind("<Control-C>", "Control-C")

    while True:
        event, values = window.read()
        print(event, values) #debug
        if event in (None, 'Exit', 'Cancel'):
            break
        
        elif event == '-CREATE-OUTPUT-':
            output = create_output_window()
            if output:
                list_output.append(output)
                window["-OUTPUT-TABLE-"].update(list_output)

        elif event == '-SUBMIT-TRANSACTION-':
            fee = int(values['-FEE-'])
            trans = createTransaction(fee, list_output)
            trans = sign_transaction(trans)
            submitTransaction(trans)

            window['-FEE-'].update('')
            list_output = []
            window['-OUTPUT-TABLE-'].update(list_output)

            # address_balance_list, wallet_balance = update_address_balance()
            # window["-ADDRESS-TABLE-"].update(address_balance_list)
            # window['-WALLET-BALANCE-'].update(wallet_balance)
        
        elif event == 'Control-C' and values["-ADDRESS-TABLE-"]:
            row = int( values["-ADDRESS-TABLE-"][0])
            address = address_balance_list[row][0] #get address
            pyperclip.copy(address)

        elif event == "Infomation":
            wallet_info_window()
        
        elif event == '-REFRESH-':
            address_balance_list, wallet_balance = update_address_balance()
            window["-ADDRESS-TABLE-"].update(address_balance_list)
            window['-WALLET-BALANCE-'].update(wallet_balance)

def main():
    result = wallet_window()
    if result == "close": return
    main_window()

if __name__ == '__main__':
    main()





ClientSocket.close()