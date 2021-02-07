from flask import Flask, jsonify, request
import random
import string
# from threading import Timer

app = Flask(__name__)

peers = dict()
malicious = dict()
consensus_group1 = dict()
consensus_group2 = dict()

_host = '127.0.0.1'
_port = '5000'

block = ""
for i in range(10):
    tau = "".join([random.choice(string.ascii_letters + string.digits) for n in range(64)])
    block += (tau + "\n")


@app.route('/', methods=['POST'])
def register_peer():
    peer = request.get_json()
    peers.update({peer['id']: peer})
    return peers, 201


@app.route('/', methods=['GET'])
def get_list():
    return jsonify(peers), 200

@app.route('/secret', methods=['POST'])
def register_malicious():
    mal = request.get_json()
    k = (len(peers) - 1) // 3
    if mal['scenario'] == 2:
        k -= 1
        malicious.update({mal['id']:peers[mal['id']]})
    elif mal['scenario'] == 3:
        k += 1
    elif mal['scenario'] == 4:
        malicious.update({mal['id']: peers[mal['id']]})

    for i in range(0,k):
        p = random.choice(list(peers.values()))
        while p['id'] == mal['id'] or p['id'] in malicious.keys():
            p = random.choice(list(peers.values()))
        malicious.update({p['id']: p})

    if mal['scenario'] == 2 or mal['scenario'] == 4:
        for peer in peers.values():
            if peer['id'] not in malicious.keys():
                if len(consensus_group1) <= (len(peers) - len(malicious)) // 2:
                    consensus_group1.update({peer['id'] : peer})
                else:
                    consensus_group2.update({peer['id'] : peer})
    print('Scenario: ' + str(mal['scenario']) + ', # of malicious peers: ' + str(len(malicious)))
    print(malicious)

    return '', 201

@app.route('/secret/malicious', methods=['POST'])
def get_mal_list():
    if request.get_json()['id'] in malicious.keys():
        return jsonify(malicious), 201
    else:
        return '', 202


@app.route('/secret/block', methods=['GET'])
def get_block():
    return jsonify({"block":block}),200

@app.route('/secret/consensus', methods=['GET'])
def get_consensus_groups():
    return jsonify([consensus_group1, consensus_group2]), 200


if __name__ == "__main__":
    app.run(host=_host, port=_port, debug=True)

# t = Timer(30.0, hello)
# t.start()