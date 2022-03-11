import random
import socket, ed25519, binascii, base58, time as time_, os, pyperclip, json
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
host = '26.49.190.114'
port = 12345

current_wallet = None

print('Waiting for connection')
try:
    ClientSocket.connect((host, port))
except socket.error as e:
    print(str(e))


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
        totalOutputAmount += each[1] # [address, amount]
    
    outputList = list(map(lambda x: TransactionOutput(x[1], x[0]), outputList))

    inputList = []
    totalInputAmount = 0
    
    for key, value in current_wallet.GetData(HdWalletBipDataTypes.ADDRESS).ToDict().items():
        privkey = value['raw_priv']
        pubkey = value['raw_compr_pub'][2:]
        address = pubkey_to_address(pubkey)

        address_UTXOs_info = get_addr_UTXO(address)
        print('address: ', address)
        print('address UTXO info: ', address_UTXOs_info)
        
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

    print(fee)
    print(totalInputAmount, totalOutputAmount)

    change = totalInputAmount - totalOutputAmount - fee
    print(change)
    if change > 0:
        addrs_dict = current_wallet.GetData(HdWalletBipDataTypes.ADDRESS).ToDict()
        random_number = random.randint(0, len(addrs_dict) - 1)
        addr_dict = addrs_dict['address_{}'.format(random_number)]
        change_output = TransactionOutput(change, pubkey_to_address(addr_dict['raw_compr_pub'][2:]))
        outputList.append(change_output)

    print(inputList)
    print(outputList[0].toJSON())
    
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
            print('corrspond private key: ', value['raw_priv'])
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
    acc_idx = 0
    addr_num = 20
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
        'derivation': derivation,
        'acc_idx': acc_idx,
        'addr_num': addr_num,
        'addr_offset': addr_offset,
    }
    save_wallet(wallet_name, data)
    global current_wallet
    current_wallet = hd_wallet

def create_wallet_from_menemonic(wallet_name: str, mnemonic: str):
    acc_idx = 0
    addr_num = 20
    addr_offset = 0

    hd_wallet_fact = HdWalletBipFactory(HdWalletBip44Coins.POLKADOT_ED25519_SLIP)
    hd_wallet = hd_wallet_fact.CreateFromMnemonic(wallet_name, mnemonic)
    hd_wallet.Generate(acc_idx=acc_idx, change_idx=HdWalletBipChanges.CHAIN_EXT, addr_num=addr_num, addr_off=addr_offset)

    mnemonic = hd_wallet.GetData(HdWalletBipDataTypes.MNEMONIC)
    derivation = "m'/44'/354'"

    data = {
        'mnemonic': mnemonic,
        'derivation': derivation,
        'acc_idx': acc_idx,
        'addr_num': addr_num,
        'addr_offset': addr_offset,
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
    save_wallet(wallet_name, data)
    global current_wallet
    current_wallet = hd_wallet
    # current_wallet = {
    #     'name': wallet_name,
    #     'data': data
    # }

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
                display_seed_window(current_wallet.GetData(HdWalletBipDataTypes.MNEMONIC))
            
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
        data = json.load(file)

    hd_wallet_fact = HdWalletBipFactory(HdWalletBip44Coins.POLKADOT_ED25519_SLIP)
    hd_wallet = hd_wallet_fact.CreateFromMnemonic(wallet_name, data['mnemonic'])
    hd_wallet.Generate(acc_idx=data['acc_idx'], change_idx=HdWalletBipChanges.CHAIN_EXT, addr_num=data['addr_num'], addr_off=data['addr_offset'])
    
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
    for address in list_address:
        amount = get_balance(address)
        wallet_balance += amount
        result.append( [address, amount] )
    
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
        [sg.Text('Seed standard', size=(20,)), sg.Text('Bip39')],
        [sg.Text('Mnemonic')],
        [sg.Multiline(mnemonic, size=(30, 5), expand_x=True)]
    ]

    window = sg.Window("LVWallet", wallet_info_layout)

    while True:
        event, values = window.read()
        if event in (None, 'Exit', 'Cancel'):
            break

def get_trans_info(trans_hash):
    data = transmitData('getTransInfo', [trans_hash])
    ClientSocket.sendall(data.encode())
    trans_info_json = json.loads(ClientSocket.recv(1048576).decode())
    return trans_info_json

def get_output_amount(trans: Transaction):
    amount = 0
    for output in trans.outputList:
        amount += output.amount
    
    return amount

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

        [sg.Text('Input: {}'.format(inputAmount))],
        [sg.Table(inputs, ['txid', 'idx'],  max_col_width=55,
                    auto_size_columns=True, justification='left', 
                    num_rows=5, key="-TRANS-INPUTS-TABLE-",
                    expand_x=True)],

        [sg.Text('Output: {}'.format(outputAmount))],
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

def main_window():
    list_output = []
    address_balance_list, wallet_balance = update_address_balance()

    global list_trans_json
    list_trans_json = get_wallet_trans_history()
    history_info = trans_history_summary_info(list_trans_json)
    
    

    menu_def = [['File', ['Recently Open', 'Open', 'New','Close']] , ['Wallet',['Infomation']]]

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
        [sg.Table(address_balance_list, headings=['address', 'balance'], max_col_width=35,
                    auto_size_columns=True, justification='left', 
                    num_rows=5, key="-ADDRESS-TABLE-",
                    expand_x=True, expand_y=True,
                    
        )],
        [sg.Button('Refresh', key='-REFRESH-ADDR-TABLE-')]
    ]

    send_layout = [
        [sg.Text('Fee'), sg.Input('0', key='-FEE-', expand_x=True)],
        [sg.Table([], headings=['address', 'amount'], max_col_width=35,
                    auto_size_columns=True, justification='left', 
                    num_rows=5, key="-OUTPUT-TABLE-",
                    expand_x=True, 
                    select_mode= sg.SELECT_MODE_BROWSE,
                    enable_events=True,
                    right_click_menu= ['Right', ['Delete']],
                    right_click_selects=True,
        )],
        [sg.Button('Create output', key='-CREATE-OUTPUT-'), sg.Button('Clear', key='-CLEAR-')],
        [sg.Button('Send', key='-SUBMIT-TRANSACTION-')],
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
        event, values = window.read(timeout= 3000)
        # print(event, values) #debug
        if event in (None, 'Exit', 'Cancel'):
            break
        
        elif event == '-CREATE-OUTPUT-':
            output = create_output_window()
            if output:
                list_output.append(output)
                window["-OUTPUT-TABLE-"].update(list_output)

        elif event == '-SUBMIT-TRANSACTION-':
            fee = int(values['-FEE-'])
            if validateAmountSpend(gettotalOutputAmount(list_output), fee, int(values['-WALLET-BALANCE-'])):
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
        
        elif event == '-REFRESH-ADDR-TABLE-':
            address_balance_list, wallet_balance = update_address_balance()
            window["-ADDRESS-TABLE-"].update(address_balance_list)
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


        address_balance_list, wallet_balance = update_address_balance()
        window["-ADDRESS-TABLE-"].update(address_balance_list)
        window['-WALLET-BALANCE-'].update(wallet_balance)

        list_trans_json = get_wallet_trans_history()
        history_info = trans_history_summary_info(list_trans_json)
        window['-HISTORY-TABLE-'].update(history_info)


def main():
    result = wallet_window()
    if result == "close": return
    main_window()

if __name__ == '__main__':
    main()





ClientSocket.close()