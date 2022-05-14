import random
import socket, ed25519, binascii, base58, time as time_, os, pyperclip, json, aes_cipher
from config import *
from Structure.Block import *
from datetime import datetime
from bitcoin import *

import PySimpleGUI as sg

wallet_path = os.path.join(root_path, 'multisig_wallets')

ClientSocket = socket.socket()
host = '192.168.1.14'
port = 12345

try:
    ClientSocket.connect((host, port))
except socket.error as e:
    print(str(e))

wallet_name = None
privkey = None
pubkey = None
address = None
cosigner_addresses = []
total_keys = None
sigs_required = None


list_trans_json = None

def submitTransaction(tran: Transaction):
    print(tran.toJSONwithSignature())
    data = transmitData('submittransaction', [tran.toJSONwithSignature()])
    ClientSocket.sendall(data.encode())

def create_script():
    script = '{} {}'.format(sigs_required, total_keys)
    for each in cosigner_addresses:
        script += ' {}'.format(each)
    
    return script

def validateAddress(address):
    addr_decode = base58.b58decode(address).hex()

    hash = addr_decode[:len(addr_decode) - 8]

    checksum = addr_decode[len(addr_decode) - 8:]

    for i in range(2):
        hash = hashlib.sha256(hash.encode()).hexdigest()

    if hash[:8] == checksum:
        return True
    return False

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
                break

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

def createTransaction(fee, outputList: list ):
    # outputList : [[address, amount], ...]
    totalOutputAmount = 0
    for each in outputList:
        totalOutputAmount += each[1] # [address, amount, script_type]
    
    outputList = list(map(lambda x: TransactionOutput(x[1], x[0], x[2]), outputList))

    inputList = []
    totalInputAmount = 0

    address_UTXOs_info = get_addr_UTXO(create_script())
    # print('address: ', address)
    # print('address UTXO info: ', address_UTXOs_info)

    for UTXO_info in address_UTXOs_info:
        txid, idx = UTXO_info['_id'][:64], int(UTXO_info['_id'][64:])
        inputAmount = UTXO_info['amount']

        newInput = TransactionInput(txid, idx)
        inputList.append(newInput)

        totalInputAmount += inputAmount

        if totalInputAmount > totalOutputAmount + fee:
            break
    

    # print(fee)
    # print(totalInputAmount, totalOutputAmount)

    change = totalInputAmount - totalOutputAmount - fee

    if change > 0:
        change_output = TransactionOutput(change, create_script(), ScriptType.P2MS)
        outputList.append(change_output)

    # print(inputList)
    # print(outputList[0].toJSON())
    
    transaction = Transaction( inputList, outputList, int(time_.time()))
    return transaction

def sign_transaction(trans: Transaction):
    privkey_obj = ed25519.SigningKey(binascii.unhexlify(privkey.encode()))
    signature = privkey_obj.sign(binascii.unhexlify(trans.hash.encode())).hex()

    input_0 = trans.inputList[0]
    if input_0.signature == None:
        pass
    else:
        for sig in input_0.signature.split(' '):
            if signature == sig:
                return trans

    for input in trans.inputList:
        if input.signature == None:
            input.publicKey = pubkey
            input.signature = signature
        else:
            input.publicKey += ' ' + pubkey
            input.signature += ' ' + signature
    
    return trans

def pubkey_to_address(pubkey: str):
    hash1 = hashlib.sha256(pubkey.encode()).hexdigest()
    hash2 = hashlib.new('ripemd160', hash1.encode()).hexdigest()

    hash3 = hashlib.sha256(hash2.encode()).hexdigest()
    hash4 = hashlib.sha256(hash3.encode()).hexdigest()

    #first 4 bytes of hash4
    checksum = hash4[:8]

    result = hash2 + checksum

    return base58.b58encode(binascii.unhexlify(result)).decode()

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

def create_new_key(wallet_name):
    global privkey,pubkey, address

    privKey_obj, pubkey_obj = ed25519.create_keypair()

    privkey = privKey_obj.to_ascii(encoding='hex').decode('utf-8')
    pubkey = pubkey_obj.to_ascii(encoding='hex').decode('utf-8')
    address = pubkey_to_address(pubkey)


def import_key(wallet_name):
    import_layout = [
        [sg.Text('Private key'), sg.Input('', key='-PRIVKEY-', expand_x=True)],
        [sg.Button('Next', key="-NEXT-")],
    ]
    window = sg.Window('Import key', import_layout)

    global privkey, pubkey, address
    while True:
        event, values = window.read()
        
        if event in (None, 'Exit', 'Cancel'):
            result = "close"
            break

        elif event == "-NEXT-":
            privkey = values['-PRIVKEY-']
            privkey_obj = ed25519.SigningKey(binascii.unhexlify(privkey.encode()))
            pubkey_obj = privkey_obj.get_verifying_key()
            pubkey = pubkey_obj.to_ascii(encoding='hex').decode('utf-8')
            address = pubkey_to_address(pubkey)
            result = 'success'
            break

    window.close()
    return result

def cosigners_window(number_keys):
    global cosigner_addresses

    cosigners_layout = [
        [sg.Text('Your address '), sg.Input(address)]
    ]


    for i in range(1, number_keys + 1):
        temp = [sg.Text('cosigner {} address'.format(i)), sg.Input('', key= '-COSIGNER{}-'.format(i), expand_x=True)]
        cosigners_layout.append(temp)

    cosigners_layout.append([
        sg.Button('Next', key="-NEXT-")
    ])

    window = sg.Window('Cosigners', cosigners_layout)

    while True:
        event, values = window.read()
        if event in (None, 'Exit', 'Cancel'):
            result = "close"
            break

        elif event == '-NEXT-':
            for i in range(1, number_keys + 1):
                cosigner_addresses.append(values['-COSIGNER{}-'.format(i)])
            
            result = 'success'
            break
    
    window.close()
    return result

def password_window():
    password_layout = [
        [sg.Text('Password'), sg.Input('', key= '-PASSWORD-', expand_x=True)],
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

def encrypted_wallet(password):
    data = {
        'privkey': privkey,
        'pubkey': pubkey,
        'address': address,
        'cosigner_addresses': cosigner_addresses,
        'total_keys': total_keys,
        'sigs_required': sigs_required
    }

    data_encrypter = aes_cipher.DataEncrypter()
    content = json.dumps(data)
    data_encrypter.Encrypt(content, password, itr_num= 10)
    enc_data = data_encrypter.GetEncryptedData().hex()
    
    return enc_data

def create_multisig_wallet(wallet_name):
    create_wallet_layout = [
        [sg.Text('Number of keys'), sg.Input('3', key= '-NUMBER-OF-KEY-', expand_x=True)],
        [sg.Text('Number of signatures required'), sg.Input('2', key= '-NUMBER-OF-SIG-REQ-', expand_x=True)],
        [sg.Radio('Create new multisig wallet', 'wallet_type', default=True, key="-NEW-WALLET-")],
        [sg.Radio('Import key', 'wallet_type', key="-IMPORT-KEY-")],
        [sg.Button('Next', key="-NEXT-")]
    ]
    window = sg.Window('Create Wallet', create_wallet_layout)
    while True:
        event, values = window.read()
        
        if event in (None, 'Exit', 'Cancel'):
            result = "close"
            break
        
        elif event == '-NEXT-':
            global total_keys, sigs_required

            total_keys = int(values['-NUMBER-OF-KEY-'])
            sigs_required = int(values['-NUMBER-OF-SIG-REQ-'])

            wallet_type = "-NEW-WALLET-" if values["-NEW-WALLET-"] else "-IMPORT-KEY-"
            if wallet_type == '-NEW-WALLET-':
                create_new_key(wallet_name)
                result = cosigners_window(int(values['-NUMBER-OF-KEY-']))
                if result == 'success':
                    return result
                
            elif wallet_type ==  "-IMPORT-KEY-":
                result = import_key(wallet_name)
                if result == 'success':
                    result = cosigners_window(int(values['-NUMBER-OF-KEY-']))
                    if result == 'success':
                        return result

    window.close()
    return result

def load_wallet(wallet_path, password):
    global wallet_name
    data_decrypter = aes_cipher.DataDecrypter()

    wallet_name = wallet_path.split('/')[-1].split('.')[0]
    with open(wallet_path, "r+") as file:
        content = binascii.unhexlify(file.read().encode())
        data_decrypter.Decrypt(content, password, itr_num= 10)
        dec_data = data_decrypter.GetDecryptedData()
    
    data = json.loads(dec_data.decode())

    global privkey, pubkey, address, cosigner_addresses, total_keys, sigs_required
    privkey = data['privkey']
    pubkey = data['pubkey']
    address = data['address']
    cosigner_addresses = data['cosigner_addresses']
    total_keys = data['total_keys']
    sigs_required = data['sigs_required']

def save_wallet(wallet_name, data):
    with open(wallet_path + f'/{wallet_name}.txt', "w+") as file:
        file.write(data)

def start_wallet():
    start_layout = [
        [sg.Button('Create Wallet', key="-CREATE-WALLET-"), sg.Input(key='-WALLET-NAME-')],
        [sg.Button('Open Wallet', key="-OPEN-WALLET-"), sg.Input(key='-WALLET-PATH-', readonly=True), sg.FileBrowse(initial_folder= wallet_path , target='-WALLET-PATH-', key="-BROWSE-")]
    ]

    window = sg.Window('Multisig Wallet', start_layout)

    while True:
        event, values = window.read()
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
                        load_wallet(values['-WALLET-PATH-'], password)
                        result = "open wallet"
                        window.close()
                        return result
                    except:
                        pass

        elif event == "-CREATE-WALLET-":
            temp =  list(os.walk('multisig_wallets'))
            if temp != []:
                _, _, filenames = temp[0]
            else:
                filenames = []

            if values['-WALLET-NAME-'] != '' and '{}.txt'.format(values['-WALLET-NAME-']) not in filenames:
                global wallet_name
                wallet_name = values['-WALLET-NAME-']
                result = create_multisig_wallet(wallet_name)
                if result == 'success':
                    result = "new wallet"

                    password = password_window()
                    while not password:
                        password = password_window()

                    enc_data = encrypted_wallet(password)
                    save_wallet(values['-WALLET-NAME-'], enc_data)
                    break

    window.close()
    return result

def get_history_info():
    data = transmitData('getaddressTransactions', [[address]])
    ClientSocket.sendall(data.encode())
    result = json.loads(ClientSocket.recv(1048675).decode())

    return result

def trans_history_summary_info(list_trans_json):
    result = []
    
    for trans_json in list_trans_json:
        trans = Transaction.from_json(trans_json)
        send_amount = 0
        for trans_output in trans.outputList:
            send_amount += trans_output.amount

        trans_date = datetime.fromtimestamp(trans.time)
        result.append( [trans_date, trans.hash, send_amount] )
    
    result.sort(key= lambda x: x[0], reverse= True)
    for each in result:
        each[0] = each[0].strftime('%d-%m-%y')

    return result

def wallet_info_window():


    wallet_info_layout = [
        [sg.Text('Wallet name:', size=(20,)), sg.Text(wallet_name)],
        [sg.Text('Script type:', size=(20,)), sg.Text('P2MS')],
        [sg.Text('Locking Script:', size=(20,)), sg.Multiline(create_script())],
    ]

    window = sg.Window("LVWallet", wallet_info_layout)

    while True:
        event, values = window.read()
        if event in (None, 'Exit', 'Cancel'):
            break
    
    window.close()


def get_balance(address):
    list_UTXOs = get_addr_UTXO(address)
    balance = 0
    for each in list_UTXOs:
        balance += each['amount']
    return balance

def show_signed_transaction(trans: Transaction):
    amount_sent = 0
    fee = 0
    script = create_script()
    for output in trans.outputList:
        if output.recvAddress != script:
            amount_sent += output.amount
        else:
            fee += output.amount

    is_sign = False
    for each in trans.inputList:
        if each.signature == None:
            is_sign = False
            break
        elif address in each.signature.split(' '):
            is_sign = True


    status_text = 'Signed' if is_sign else  'Unsigned'

    # for each in trans.inputList:
    #     print(each.toJSON())

    inputs = [[each.txid, each.idx] for each in trans.inputList]
    outputs = [[each.recvAddress, each.amount] for each in trans.outputList]

    return_result = None

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
        
        [sg.Button('Save', key='-SAVE-'), sg.Button('Sign', key='-SIGN-'), sg.Button('Send', key='-SEND-')]
    ]

    window = sg.Window('Transaction', trans_detail_layout)

    sign_trans = None

    while True:
        event, values = window.read()
        if event in (None, 'Exit', 'Cancel'):
            break

        elif event == '-SAVE-':
            trans_to_file(trans)
        
        elif event == '-SIGN-':
            if not is_sign:
                sign_trans = sign_transaction(trans)
                is_sign = True
                window['-STATUS-'].update('Status: Signed')
        
        elif event == '-SEND-':
            if is_sign:
                submitTransaction(sign_trans)
                return_result = 'Sent'
                break
    
    window.close()
    return return_result

def trans_to_file(trans: Transaction):
    path = os.path.join(root_path, 'Trans_file')
    with open(path + f'/{trans.hash}.txt', "w+") as file:
        json.dump(trans.toJSONwithSignature(), file, sort_keys=True, indent= 4, separators=(', ', ': '))

def file_to_trans(path):
    with open(path, "r+") as file:
        trans_json = json.load(file)
    
    return Transaction.from_json(trans_json)

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
    
    window.close()

def update_list_output(trans: Transaction):
    result = []
    for output in trans.outputList:
        result.append([output.recvAddress, output.amount, output.script_type])
    
    return result

def main_window():
    menu_def = [['File', ['Recently Open', 'Open', 'New','Close']] , ['Wallet',['Information']]]
    list_output = []

    

    is_sign = False
    sign_trans = None

    global list_trans_json
    list_trans_json = get_history_info()
    history_info = trans_history_summary_info(list_trans_json)

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
        [sg.Button('Import', key='-IMPORT-TRANSACTION-'), sg.Button('Open', key='-OPEN-TRANSACTION-')],
    ]

    wallet_balance = get_balance(create_script())
    main_layout = [
        [sg.Menu(menu_def)],
        [sg.TabGroup([
            [sg.Tab("Send", send_layout)],
            [sg.Tab("History", history_layout)]
        ], tab_background_color='grey', selected_background_color='white', selected_title_color='black')],
        [sg.Text('Balance'), sg.Input(wallet_balance, readonly=True, key='-WALLET-BALANCE-')]
    ]

    window = sg.Window('Multisig Wallet', main_layout)

    while True:
        event, values = window.read(timeout= 5000)
        if event in (None, 'Exit', 'Cancel'):
            break
            
        elif event == '-REFRESH-HISTORY-TABLE-':
            list_trans_json = get_history_info()
            history_info = trans_history_summary_info(list_trans_json)
            window['-HISTORY-TABLE-'].update(history_info)

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
            if sign_trans == None:
                fee = int(values['-FEE-'])
                sign_trans = createTransaction(fee, list_output)

        # if not is_sign:
        #     sign_trans = sign_transaction(sign_trans)
        #     is_sign = True

            result = show_signed_transaction(sign_trans)

            if result == 'Sent':
                window['-FEE-'].update('')
                list_output = []
                window['-OUTPUT-TABLE-'].update(list_output)

                sign_trans = None
                is_sign = False
            ## open Transaction

        elif event == '-SUBMIT-TRANSACTION-':
            if sign_trans and is_sign:
                submitTransaction(sign_trans)

        elif event == 'Information':
            wallet_info_window()

        elif event == '-IMPORT-TRANSACTION-':
            path = sg.popup_get_file('Choose file')
            if path != '' or path != None:
                sign_trans = file_to_trans(path)
                is_sign = False

                list_output = update_list_output(sign_trans)
                window["-OUTPUT-TABLE-"].update(list_output)
        
        elif event == '-CLEAR-':
            list_output = []
            window["-OUTPUT-TABLE-"].update(list_output)

            sign_trans = None
            is_sign = False
        
        elif event == 'Details':
            row = int( values["-HISTORY-TABLE-"][0])
            trans_hash = history_info[row][1]
            # print('row: ', row, 'trans_hash: ', trans_hash)
            show_trans_detail(trans_hash)
        
        elif event == 'Delete':
            row = int( values["-OUTPUT-TABLE-"][0])
            list_output.pop(row)
            window['-OUTPUT-TABLE-'].update(list_output)

        wallet_balance = get_balance(create_script())
        window['-WALLET-BALANCE-'].update(wallet_balance)

def main():
    result = start_wallet()
    if result == "close": return
    main_window()

if __name__ == '__main__':
    main()
