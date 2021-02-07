import string
from Crypto.Hash import SHA3_256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
import requests
import zmq
import os
from multiprocessing import Process
import time
import random
import sys
import json


def send(_senderid, _peers, _message):
    context = zmq.Context()
    for leer in _peers.values():
        socket_push = context.socket(zmq.PUSH)
        if leer['id'] != _senderid:
            # print("process " + str(_senderid) + " going conn")
            socket_push.connect("tcp://" + str(leer['ip-port']))
            # print("process " + str(_senderid) + " going send")
            socket_push.send_json(_message)
            time.sleep(1)  # change: new line
            socket_push.close()


def validate(_block, _sig, _pkey, _h_prev_hex):
    sig = int(_sig).to_bytes(64, byteorder='big')
    ell = len(_block)
    pkey = ECC.import_key(_pkey)
    print()
    print(_pkey)
    print()

    verifier = DSS.new(pkey, 'fips-186-3')

    h = SHA3_256.new(_block.encode('utf-8') + bytes.fromhex(_h_prev_hex))  # CEHCK
    try:
        verifier.verify(h, sig)
        print("The block is authentic.")
        return True
    except ValueError:
        print("The block is NOT authentic.")
        print(str(h))
        return False


def peer(pid, pport, ht, ell, num_of_round, scenario):
    print("Peer is started:" + str(os.getpid()))
    pid = os.getpid()
    folderName = "Sc"+str(scenario)+"_"+"Peer_" + str(pid)
    path = os.path.join(os.getcwd(), folderName)
    if not os.path.exists(folderName):
        os.makedirs(folderName)
    print(path)

    index_server = 'http://127.0.0.1:5000'
    ip_port = '127.0.0.1:' + str(pport)
    known_peers = dict()
    random_vars_counter = 0

    # generate public-key
    sign_key = ECC.generate(curve='NIST P-256')
    verify_key = sign_key.public_key()
    signer = DSS.new(sign_key, 'fips-186-3')

    # register index server
    response = requests.post(index_server, json={'id': pid, 'ip-port': ip_port, 'public-key': verify_key.export_key(format='OpenSSH')})
    if response.status_code == 201:
        known_peers = response.json()

    time.sleep(4)

    # check if all peers are registered
    while True:
        response = requests.get(index_server)
        if response.status_code == 200 and response.json() == known_peers:
            break
        known_peers = response.json()
        # print("process " + str(pid) + " get: \n response: " + str(response.json()) + "\n known peers: " + str(known_peers) + "\n")
        time.sleep(1)

    # generate random variable
    random_num = random.randrange(0, 2 ** 256 - 1)

    # pull random variables from peers
    context = zmq.Context()
    socket_pull = context.socket(zmq.PULL)
    socket_pull.bind("tcp://" + ip_port)
    # print("process " + str(pid) + " pull socket")

    # send the random variable to all peers
    send(pid, known_peers, {'id': pid, 'random-num': random_num})
    known_peers[str(pid)]['random-num'] = random_num

    while random_vars_counter < len(known_peers) - 1:
        # print("process " + str(pid) + " going receive")
        response = socket_pull.recv_json()
        # print("process " + str(pid) + " received")
        known_peers[str(response['id'])].update({'random-num': response['random-num']})
        # print("process " + str(pid) + " random added: " + str(random_vars_counter))
        random_vars_counter += 1
    # print("process " + str(pid) + "pull finished")

    # elect proposer
    xored_num = 0
    for leer in known_peers.values():
        # print("process " + str(pid) + "random xor: " + str(leer))
        xored_num ^= leer['random-num']

    # sha
    digest = SHA3_256.new(xored_num.to_bytes(32, byteorder='big'))
    for t in range(ht - 1):  # changed '100' to '99'
        digest = SHA3_256.new(digest.digest())  # changed: new line
    proposer_id = int.from_bytes(digest.digest(), "big") % pow(2, 24)

    # find successor peer
    first = proposer_id
    diff = float("inf")
    minid = float("inf")
    for peer in known_peers.values():
        if peer['id'] < minid:
            minid = peer['id']
        if first <= peer['id'] and abs(first - peer['id']) < diff:
            proposer_id = peer['id']
    if (proposer_id == first):
        proposer_id = minid

    print("process " + str(pid) + "election finished: PROPOSER_ID = " + str(proposer_id))
    malicious = False
    secret_server = 'http://127.0.0.1:5000/secret'
    consensus_groups = []

    if pid == proposer_id:
        response = requests.post(secret_server, json={'id': pid, 'scenario': scenario})

    else:
        time.sleep(4)

    malicious_server = 'http://127.0.0.1:5000/secret/malicious'
    known_malicious = dict()
    response = requests.post(malicious_server, json={'id': pid})
    if response.status_code == 201:
        malicious = True
        known_malicious = response.json()

    print("Process " + str(pid) + "malicious? " + str(malicious))

    if malicious:
        print('Malicious List in Process ' + str(pid) + " = " + str(known_malicious))

        block_server = 'http://127.0.0.1:5000/secret/block'
        response = requests.get(block_server)
        malicious_block = response.json()['block']

        honest_peers = dict()
        for p in known_peers.keys():
            if p not in known_malicious.keys():
                honest_peers.update({p: known_peers[p]})

        if scenario == 2 or scenario == 4:
            consensus_server = 'http://127.0.0.1:5000/secret/consensus'
            consensus_groups = requests.get(consensus_server).json()
            print(consensus_groups)

    # file operations
    randoms_n_elected = ''
    f = open("election_" + str(pid) + ".log", "w+")  # wT
    for leer in known_peers.values():
        f.write(str(leer['random-num']) + "\n")
        randoms_n_elected += str(leer['random-num']) + "\n"  # changed: '+ "\n" added'
    f.write(str(proposer_id) + "\n")
    randoms_n_elected += str(proposer_id) + "\n"  # changed: '+ "\n" added'

    signature = signer.sign(SHA3_256.new(randoms_n_elected.encode()))  # check
    signature_str = str(int.from_bytes(signature, "big"))
    f.write(signature_str + "\n")

    f.write(verify_key.export_key(format='OpenSSH'))
    f.close()
    # print('Process ' + str(pid) + ' finished writing its log file...')

    h_prev = SHA3_256.new("".encode('utf-8'))

    if pid == proposer_id:
        fi = open('publickeys.txt','wt')
        pkeys = dict()
        for leer in known_peers.values():
            pkeys[leer['id']] = leer['public-key'] + "\n"
        fi.write(json.dumps(pkeys))
        fi.close()
        print('publickeys.txt created')
        if not malicious:
            for round_num in range(0, num_of_round):
                print("/********************** ROUND " + str(round_num) + " ********************/")
                # generate a block of randomly created transaction
                block = ""
                for i in range(ell):
                    tau = "".join([random.choice(string.ascii_letters + string.digits) for n in range(64)])
                    block += (tau + "\n")
                print('Proposer ' + str(pid) + ' finished creating transactions...')

                # sign block
                h = SHA3_256.new(block.encode('utf-8') + h_prev.digest())
                signature = signer.sign(h)

                # send id,block, signature, previous hash, round # to all peers
                send(pid, known_peers,
                     {'id': pid, 'block': block, 'signature': str(int.from_bytes(signature, "big")),
                      'h_prev': h_prev.hexdigest(), 'round': round_num})
                print('Proposer ' + str(pid) + ' finished sending transactions...')

                # wait for validators' messages to validate
                signs = []
                for i in range(len(known_peers) - 1):
                    response = socket_pull.recv_json()
                    recv_block = response['block']
                    peers_pkey = known_peers[str(response['id'])]['public-key']

                    # if sign is valid, append into validated signs array
                    if block == recv_block and validate(recv_block, response['signature'], peers_pkey, response['h_prev']):
                        signs.append({"pid": response['id'], "signature": str(response['signature'])})#str(int.from_bytes(response['signature'], "big"))

                h_prev = SHA3_256.new(block.encode('utf-8') + h_prev.digest())
                signs.append({"pid": pid, "signature": str(int.from_bytes(signature, "big"))})
                if len(signs) > (len(known_peers) - 1) * 2 / 3:
                    fileName = os.path.join(path, 'block_' + str(round_num) + '_0' + '.log')
                    f = open(fileName, 'wt')
                    f.write(block + json.dumps(signs))
                    f.close()
                    print("Proposer " + str(pid) + " accepted block " + str(round_num) + " with " + str(
                        len(signs)) + " signatures...")
                else:
                    print("Proposer " + str(pid) + " rejected block " + str(round_num) + " with " + str(
                        len(signs)) + " signatures...")
                print("/----------------------- END OF ROUND " + str(round_num) + " IN PROPOSER ********************/")
                time.sleep(5)
        else:
            other_malicious = dict()
            for mal in known_malicious.values():
                if pid != mal['id']:
                    other_malicious.update({mal['id'] : mal})

            for round_num in range(0, num_of_round):
                print("/********************** ROUND " + str(round_num) + " ********************/")
                # generate a block of randomly created transaction
                block = ""
                for i in range(ell):
                    tau = "".join([random.choice(string.ascii_letters + string.digits) for n in range(64)])
                    block += (tau + "\n")
                print('Proposer ' + str(pid) + ' finished creating transactions...')

                # sign block
                h = SHA3_256.new(block.encode('utf-8') + h_prev.digest())
                signature = signer.sign(h)

                if round_num != 4:
                    # send id,block, signature, previous hash, round # to all peers
                    send(pid, known_peers,
                         {'id': pid, 'block': block, 'signature': str(int.from_bytes(signature, "big")),
                          'h_prev': h_prev.hexdigest(), 'round': round_num})
                    print('Proposer ' + str(pid) + ' finished sending transactions...')

                    # wait for validators' messages to validate
                    signs = []
                    for i in range(len(known_peers) - 1):
                        response = socket_pull.recv_json()
                        recv_block = response['block']
                        peers_pkey = known_peers[str(response['id'])]['public-key']

                        # if sign is valid, append into validated signs array
                        if block == recv_block and validate(recv_block, response['signature'], peers_pkey,
                                                            response['h_prev']):
                            signs.append({"pid": response['id'], "signature": str(
                                response['signature'])})  # str(int.from_bytes(response['signature'], "big"))

                    h_prev = SHA3_256.new(block.encode('utf-8') + h_prev.digest())
                    signs.append({"pid": pid, "signature": str(int.from_bytes(signature, "big"))})
                    if len(signs) > (len(known_peers) - 1) * 2 / 3:
                        print("Proposer " + str(pid) + " accepted block " + str(round_num) + " with " + str(
                            len(signs)) + " signatures...")
                    else:
                        print("Proposer " + str(pid) + " rejected block " + str(round_num) + " with " + str(
                            len(signs)) + " signatures...")
                    print("/----------------------- END OF ROUND " + str(round_num) + " IN PROPOSER ********************/")
                    time.sleep(3)
                else:
                    print("*********************CONSENSUS GROUPS:-----------------------------")
                    print(consensus_groups)
                    h2 = SHA3_256.new(malicious_block.encode('utf-8') + h_prev.digest())
                    signature2 = signer.sign(h2)
                    print("H1 PROPOSER:" + str(h))
                    print("H2 PROPOSER:" + str(h2))

                    send(pid, consensus_groups[0],
                         {'id': pid, 'block': block, 'signature': str(int.from_bytes(signature, "big")),
                          'h_prev': h_prev.hexdigest(), 'round': round_num})

                    send(pid, consensus_groups[1],
                         {'id': pid, 'block': malicious_block, 'signature': str(int.from_bytes(signature2, "big")),
                          'h_prev': h_prev.hexdigest(), 'round': round_num})
                    print('*********************=====================================================')
                    print(other_malicious)
                    send(pid, other_malicious,
                         {'id': pid, 'block': block, 'signature': str(int.from_bytes(signature, "big")),
                          'h_prev': h_prev.hexdigest(), 'round': round_num})

                    print('Proposer ' + str(pid) + ' finished sending transactions...')
                    # wait for validators' messages to validate
                    signs = []
                    for i in range(len(honest_peers)):
                        response = socket_pull.recv_json()

                    h_prev = SHA3_256.new(block.encode('utf-8') + h_prev.digest())
                    print("/----------------------- END OF ROUND " + str(
                        round_num) + " IN PROPOSER ********************/")
                    time.sleep(3)

    else:
        round_num = 0
        if not malicious:
            while round_num < num_of_round:
                current_block = ""
                other_block = ""
                signs = []
                signs2 = []
                h_prev_hex = ""
                for i in range(len(known_peers) - 1):
                    response = socket_pull.recv_json()

                    if current_block == "" and response['id'] == proposer_id:
                        # setup variables
                        current_block = response['block']
                        h_prev_hex = response['h_prev']
                        round_num = response['round']
                        proposers_pkey = known_peers[str(proposer_id)]['public-key']
                        print('Validator ' + str(pid) + ' received a new block from proposer...')

                        if validate(current_block, response['signature'], proposers_pkey, h_prev_hex):
                            signs.append({'pid': response['id'], 'signature': response['signature']})

                            h = SHA3_256.new(current_block.encode('utf-8') + bytes.fromhex(h_prev_hex))
                            signature = signer.sign(h)

                            send(pid, known_peers, {'id': pid, 'block': current_block,
                                                    'signature': str(int.from_bytes(signature, "big")),
                                                    'h_prev': h_prev_hex, 'round': round_num})

                            print('Validator ' + str(pid) + ' validated a block...')


                    elif current_block == response['block'] and response['id'] != proposer_id:
                        peers_pkey = known_peers[str(response['id'])]['public-key']
                        print('Validator ' + str(pid) + ' received a new block from validator...')
                        if validate(response['block'], response['signature'], peers_pkey, h_prev_hex):
                            signs.append({"pid": response['id'], "signature": response['signature']})

                    elif current_block != response['block'] and response['id'] != proposer_id:
                        other_block = response['block']
                        peers_pkey = known_peers[str(response['id'])]['public-key']
                        print(other_block)
                        if validate(other_block, response['signature'], peers_pkey, h_prev_hex):
                            signs2.append({"pid": response['id'], "signature": response['signature']})

                signs.append({"pid": pid, "signature": str(int.from_bytes(signature, "big"))})
                if len(signs) > (len(known_peers) - 1) * 2 / 3:
                    fileName = os.path.join(path,'block_' + str(round_num) + '_0' + '.log')
                    f = open(fileName, 'wt')
                    f.write(current_block + json.dumps(signs))
                    f.close()
                    print("Validator " + str(pid) + " accepted block " + str(round_num) + "_0 with " + str(
                        len(signs)) + " signatures...")

                else:
                    print("Validator " + str(pid) + " rejected block " + str(round_num) + "_0 with " + str(
                        len(signs)) + " signatures...")

                if len(signs2) > (len(known_peers) - 1) * 2 / 3:
                    fileName = os.path.join(path,'block_' + str(round_num) + '_1' + '.log')
                    f = open(fileName, 'wt')
                    f.write(other_block + json.dumps(signs2))
                    f.close()
                    print("Validator " + str(pid) + " accepted block " + str(round_num) + "_1 with " + str(
                        len(signs2)) + " signatures...")

                else:
                    print("Validator " + str(pid) + " rejected block " + str(round_num) + "_1 with " + str(
                        len(signs2)) + " signatures...")
                round_num += 1
                current_block = ""
                print("/----------------------- END OF ROUND " + str(round_num) + " IN VALIDATOR ********************/")
        else:
            while round_num < num_of_round:
                signs = []
                h_prev_hex = ""
                current_block = ""
                if round_num != 4:
                    for i in range(len(known_peers) - 1):
                        response = socket_pull.recv_json()

                        if current_block == "" and response['id'] == proposer_id:
                            # setup variables
                            current_block = response['block']
                            h_prev_hex = response['h_prev']
                            round_num = response['round']
                            proposers_pkey = known_peers[str(proposer_id)]['public-key']
                            print('Validator ' + str(pid) + ' received a new block from proposer...')

                            if validate(current_block, response['signature'], proposers_pkey, h_prev_hex):
                                signs.append({'pid': response['id'], 'signature': response['signature']})

                                h = SHA3_256.new(current_block.encode('utf-8') + bytes.fromhex(h_prev_hex))
                                signature = signer.sign(h)

                                send(pid, known_peers, {'id': pid, 'block': current_block,
                                                        'signature': str(int.from_bytes(signature, "big")),
                                                        'h_prev': h_prev_hex, 'round': round_num})

                                print('Validator ' + str(pid) + ' validated a block...')


                        elif current_block == response['block'] and response['id'] != proposer_id:
                            peers_pkey = known_peers[str(response['id'])]['public-key']

                            if validate(response['block'], response['signature'], peers_pkey, h_prev_hex):
                                signs.append({"pid": response['id'], "signature": response['signature']})

                    signs.append({"pid": pid, "signature": str(int.from_bytes(signature, "big"))})
                    if len(signs) > (len(known_peers) - 1) * 2 / 3:
                        print("Validator " + str(pid) + " accepted block " + str(round_num) + " with " + str(
                            len(signs)) + " signatures...")

                else:
                    if scenario == 2 or scenario == 4:
                        for i in range(len(honest_peers) + 1):
                            response = socket_pull.recv_json()
                            if response['id'] == proposer_id:
                                print('Malicious received block for PROPOSER')
                                h_prev_hex = response['h_prev']
                                round_num = response['round']
                                block = response['block']
                                h = SHA3_256.new(block.encode('utf-8') + bytes.fromhex(h_prev_hex))
                                print("Mal_H: " + str(h))
                                signature = signer.sign(h)
                                h2 = SHA3_256.new(malicious_block.encode('utf-8') + bytes.fromhex(h_prev_hex))
                                signature2 = signer.sign(h2)
                                print("Mal_H2: " + str(h2))

                                send(pid, consensus_groups[0], {'id': pid, 'block': block,
                                                         'signature': str(int.from_bytes(signature, "big")),
                                                         'h_prev': h_prev_hex, 'round': round_num})
                                send(pid, consensus_groups[1], {'id': pid, 'block': malicious_block,
                                                         'signature': str(int.from_bytes(signature2, "big")),
                                                         'h_prev': h_prev_hex, 'round': round_num})

                    else:
                        for i in range(len(honest_peers)):
                            response = socket_pull.recv_json()
                            if response['id'] == proposer_id:
                                h_prev_hex = response['h_prev']
                                round_num = response['round']
                                h = SHA3_256.new(malicious_block.encode('utf-8') + bytes.fromhex(h_prev_hex))
                                signature = signer.sign(h)
                                send(pid, honest_peers, {'id': pid, 'block': malicious_block,
                                                        'signature': str(int.from_bytes(signature, "big")),
                                                        'h_prev': h_prev_hex, 'round': round_num})

                round_num += 1


        # for debug
        # time.sleep(1)
        # send(pid, known_peers, savior)

    print("/***************** PROCCESS " + str(os.getpid()) + " TERMINATED *************/")


if __name__ == '__main__':
    consumers = []
    number_of_peers = 7
    t = 100
    l = 10
    r = 5
    s = 1

    for i in range(0, number_of_peers):  # check
        consumers.append(Process(target=peer, args=(
            i, i + 9000, t, l, r, s)))  # -n 3 -t 100 -l 10 -r 5
        print("Peer is created:" + str(consumers[i]))
        consumers[i].start()

    for consumer in consumers:
        consumer.join()

