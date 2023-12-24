from flask import Flask, request, jsonify
import hashlib
import json
import os

app = Flask(__name__)

# This is the key-value storage for the fingerprints and associated data
fp_to_entity_info = {}
pub_to_gid = {}
gid_db = {}
msg_hash_to_msg = {}


def compute_fingerprint(entity_info):
    """ Compute the SHA256 fingerprint of the entity info. """
    entity_info_bytes = bytes.fromhex(entity_info)
    return hashlib.sha256(entity_info_bytes).hexdigest()

@app.route('/entityInfo', methods=['POST'])
def storeEntityInfo():
    entity_info = request.json.get('entityInfo')
    fingerprint = request.json.get('fingerprint')
    
    fp_to_entity_info[fingerprint] = entity_info

    return jsonify({}), 200

@app.route('/dumpData', methods=['GET'])
def dumpData():
    with open('fp_to_entity_info.json', 'w') as file:
        json.dump(fp_to_entity_info, file)
    with open('pub_to_gid.json', 'w') as file:
        json.dump(pub_to_gid, file)
    with open('gid_db.json', 'w') as file:
        json.dump(gid_db, file)
    with open('msg_hash_to_msg.json', 'w') as file:
        json.dump(msg_hash_to_msg, file)

    return jsonify({'message': 'Data dumped successfully'}), 200

@app.route('/loadData', methods=['GET'])
def loadData():
    if os.path.exists('fp_to_entity_info.json'):
        with open('fp_to_entity_info.json', 'r') as file:
            global fp_to_entity_info
            fp_to_entity_info = json.load(file)
    if os.path.exists('pub_to_gid.json'):
        with open('pub_to_gid.json', 'r') as file:
            global pub_to_gid
            pub_to_gid = json.load(file)
    if os.path.exists('gid_db.json'):
        with open('gid_db.json', 'r') as file:
            global gid_db
            gid_db = json.load(file)
    if os.path.exists('msg_hash_to_msg.json'):
        with open('msg_hash_to_msg.json', 'r') as file:
            global msg_hash_to_msg
            msg_hash_to_msg = json.load(file)

    return jsonify({'message': 'Data loaded successfully'}), 200

@app.route('/entityInfo', methods=['GET'])
def getEntityInfo():
    fingerprint = request.args.get('fingerprint')
    return jsonify(fp_to_entity_info.get(fingerprint, '')), 200

@app.route('/', methods=['GET'])
def home():
    return jsonify({}), 200

@app.route('/groupInfo', methods=['POST'])
def storeGroupInfo():
    groupID = request.json.get('groupID')
    groupInfo = request.json.get('groupInfo')
    signature = request.json.get('signature')
    pubKey = request.json.get('pubKey')

    if pubKey in pub_to_gid:
        pub_to_gid[pubKey].append(groupID)
    else:
        pub_to_gid[pubKey] = [groupID]

    if groupID in gid_db:
        gid_db[groupID]['signatures'][pubKey] = signature
    else:
        gid_db[groupID] = {
            'groupInfo': groupInfo, 
            'signatures': {pubKey: signature}, 
            'shareDataStore': {},
            'individualPublicKey': {},
            'groupKeyInfoStore': {},
            'messageStore': {},
        }

    return jsonify({}), 200

@app.route('/groupInfo', methods=['GET'])
def getGroupInfo():
    groupID = request.args.get('groupID')
    pubKey = request.args.get('pubKey')

    if groupID in gid_db:
        return jsonify({'signature': gid_db[groupID]['signatures'][pubKey], 
                        'groupInfo': gid_db[groupID]['groupInfo']}), 200

    else:
        return jsonify({}), 404


@app.route('/groupID', methods=['GET'])
def getGroupID():
    pubKey = request.args.get('pubKey')
    return jsonify(pub_to_gid.get(pubKey, [])), 200

@app.route('/shareData', methods=['POST'])
def storeShareData():
    groupID = request.json.get('groupID')
    shareData = request.json.get('shareData')
    pubKey = request.json.get('pubKey')

    if groupID in gid_db:
        gid_db[groupID]['shareDataStore'][pubKey] = shareData
    else:
        return jsonify({}), 404

    return jsonify({}), 200

@app.route('/shareData', methods=['GET'])
def getShareData():
    groupID = request.args.get('groupID')
    pubKey = request.args.get('pubKey')

    if groupID in gid_db:
        if pubKey not in gid_db[groupID]['shareDataStore']:
            return jsonify({}), 404

        return jsonify({'shareData': gid_db[groupID]['shareDataStore'][pubKey]}), 200
    else:
        return jsonify({}), 404

@app.route('/individualPublicKey', methods=['POST'])
def storeIndividualPublicKey():
    groupID = request.json.get('groupID')
    pubKey = request.json.get('pubKey')
    individualPublicKey = request.json.get('individualPublicKey')

    if groupID in gid_db:
        gid_db[groupID]['individualPublicKey'][pubKey] = individualPublicKey
    else:
        return jsonify({}), 404

    return jsonify({}), 200

@app.route('/individualPublicKey', methods=['GET'])
def getIndividualPublicKey():
    groupID = request.args.get('groupID')
    pubKey = request.args.get('pubKey')

    if groupID in gid_db:
        if pubKey not in gid_db[groupID]['individualPublicKey']:
            return jsonify({}), 404

        return jsonify({'individualPublicKey': gid_db[groupID]['individualPublicKey'][pubKey]}), 200
    else:
        return jsonify({}), 404

@app.route('/groupKeyInfo', methods=['POST'])
def storeGroupKeyInfo():
    groupID = request.json.get('groupID')
    pubKey = request.json.get('pubKey')
    groupKeyInfo = request.json.get('groupKeyInfo')
    signature = request.json.get('signature')

    if groupID in gid_db:
        gid_db[groupID]['groupKeyInfoStore'][pubKey] = {'groupKeyInfo': groupKeyInfo, 'signature': signature}
    else:
        return jsonify({}), 404

    return jsonify({}), 200

@app.route('/groupKeyInfo', methods=['GET'])
def getGroupKeyInfo():
    groupID = request.args.get('groupID')
    pubKey = request.args.get('pubKey')

    if groupID in gid_db:
        if pubKey not in gid_db[groupID]['groupKeyInfoStore']:
            return jsonify({}), 404

        return jsonify(gid_db[groupID]['groupKeyInfoStore'][pubKey]), 200
    else:
        return jsonify({}), 404

@app.route('/message', methods=['POST'])
def storeMessage():
    groupID = request.json.get('groupID')
    pubKey = request.json.get('pubKey')
    msg = request.json.get('msg')

    msgHash = hashlib.sha256(bytes.fromhex(msg)).hexdigest()
    msg_hash_to_msg[msgHash] = msg

    if groupID in gid_db:
        gid_db[groupID]['messageStore'][msgHash] = {
            'initiator': pubKey, 
            'msg': msg, 
            'parties': [], 
            'data': {
                'shareDataListStore': {},
                'QIListStore': {},
                'keyInfoListStore': {},
                'rcvPkInfoListStore': [],
                'sndPkInfoListStore': [],
                'rcvEncMsgListStore': [],
                'sndMascotListStore': [],
            }}
    else:
        return jsonify({}), 404

    return jsonify({'msgHash': msgHash}), 200

@app.route('/message', methods=['GET'])
def getMessage():
    groupID = request.args.get('groupID')

    if groupID in gid_db:
        return jsonify([{
            'msgHash': msgHash, 
            'parties': len(gid_db[groupID]['messageStore'][msgHash]['parties'])
        } for msgHash in gid_db[groupID]['messageStore']])
    else:
        return jsonify({}), 404

@app.route('/messageHash', methods=['GET'])
def getMessageHash():
    msgHash = request.args.get('msgHash')
    return jsonify(msg_hash_to_msg.get(msgHash, '')), 200

@app.route('/approveMessage', methods=['POST'])
def approveMessage():
    groupID = request.json.get('groupID')
    pubKey = request.json.get('pubKey')
    msgHash = request.json.get('msgHash')

    if groupID in gid_db:
        if msgHash in gid_db[groupID]['messageStore']:
            if pubKey not in gid_db[groupID]['messageStore'][msgHash]['parties']:
                gid_db[groupID]['messageStore'][msgHash]['parties'].append(pubKey)
            else:
                return jsonify({}), 200
        else:
            return jsonify({}), 404
    else:
        return jsonify({}), 404

    return jsonify({}), 200

@app.route('/sign/parties', methods=['GET'])
def getParties():
    groupID = request.args.get('groupID')
    msgHash = request.args.get('msgHash')

    if groupID in gid_db:
        if msgHash in gid_db[groupID]['messageStore']:
            return jsonify(gid_db[groupID]['messageStore'][msgHash]['parties']), 200
        else:
            return jsonify({}), 404
    else:
        return jsonify({}), 404

@app.route('/sign/shareDataList', methods=['POST'])
def postShareDataList():
    groupID = request.json.get('groupID')
    pubKey = request.json.get('pubKey')
    msgHash = request.json.get('msgHash')
    shareDataList = request.json.get('shareDataList')

    if groupID in gid_db:
        if msgHash in gid_db[groupID]['messageStore']:
            if pubKey in gid_db[groupID]['messageStore'][msgHash]['parties']:
                gid_db[groupID]['messageStore'][msgHash]['data']['shareDataListStore'][pubKey] = shareDataList
            else:
                return jsonify({}), 404
        else:
            return jsonify({}), 404
    else:
        return jsonify({}), 404
    
    return jsonify({}), 200

@app.route('/sign/shareDataList', methods=['GET'])
def getShareDataList():
    groupID = request.args.get('groupID')
    pubKey = request.args.get('pubKey')
    msgHash = request.args.get('msgHash')

    if groupID in gid_db:
        if msgHash in gid_db[groupID]['messageStore']:
            if pubKey in gid_db[groupID]['messageStore'][msgHash]['data']['shareDataListStore']:
                return jsonify(gid_db[groupID]['messageStore'][msgHash]['data']['shareDataListStore'][pubKey]), 200
            else:
                return jsonify({}), 404
        else:
            return jsonify({}), 404
    else:
        return jsonify({}), 404
    
    return jsonify({}), 200

@app.route('/sign/QIList', methods=['POST'])
def postQIList():
    groupID = request.json.get('groupID')
    pubKey = request.json.get('pubKey')
    msgHash = request.json.get('msgHash')
    QIList = request.json.get('QIList')

    if groupID in gid_db:
        if msgHash in gid_db[groupID]['messageStore']:
            if pubKey in gid_db[groupID]['messageStore'][msgHash]['parties']:
                gid_db[groupID]['messageStore'][msgHash]['data']['QIListStore'][pubKey] = QIList
            else:
                return jsonify({}), 404
        else:
            return jsonify({}), 404
    else:
        return jsonify({}), 404
    
    return jsonify({}), 200

@app.route('/sign/QIList', methods=['GET'])
def getQIList():
    groupID = request.args.get('groupID')
    pubKey = request.args.get('pubKey')
    msgHash = request.args.get('msgHash')

    if groupID in gid_db:
        if msgHash in gid_db[groupID]['messageStore']:
            if pubKey in gid_db[groupID]['messageStore'][msgHash]['data']['QIListStore']:
                return jsonify(gid_db[groupID]['messageStore'][msgHash]['data']['QIListStore'][pubKey]), 200
            else:
                return jsonify({}), 404
        else:
            return jsonify({}), 404
    else:
        return jsonify({}), 404
    
    return jsonify({}), 200

@app.route('/sign/keyInfoList', methods=['POST'])
def postKeyInfoList():
    groupID = request.json.get('groupID')
    pubKey = request.json.get('pubKey')
    msgHash = request.json.get('msgHash')
    keyInfoList = request.json.get('keyInfoList')
    signatureList = request.json.get('signatureList')

    if groupID in gid_db:
        if msgHash in gid_db[groupID]['messageStore']:
            if pubKey in gid_db[groupID]['messageStore'][msgHash]['parties']:
                gid_db[groupID]['messageStore'][msgHash]['data']['keyInfoListStore'][pubKey] = {'keyInfoList': keyInfoList, 'signatureList': signatureList}
            else:
                return jsonify({}), 404
        else:
            return jsonify({}), 404
    else:
        return jsonify({}), 404
    
    return jsonify({}), 200

@app.route('/sign/keyInfoList', methods=['GET'])
def getKeyInfoList():
    groupID = request.args.get('groupID')
    pubKey = request.args.get('pubKey')
    msgHash = request.args.get('msgHash')

    if groupID in gid_db:
        if msgHash in gid_db[groupID]['messageStore']:
            if pubKey in gid_db[groupID]['messageStore'][msgHash]['data']['keyInfoListStore']:
                return jsonify(gid_db[groupID]['messageStore'][msgHash]['data']['keyInfoListStore'][pubKey]), 200
            else:
                return jsonify({}), 404
        else:
            return jsonify({}), 404
    else:
        return jsonify({}), 404
    
    return jsonify({}), 200

@app.route('/sign/mtaData', methods=['POST'])
def postMtaData():
    groupID = request.json.get('groupID')
    pubKey = request.json.get('pubKey')
    msgHash = request.json.get('msgHash')
    mtaData = request.json.get('mtaData')
    mtaDataType = request.json.get('mtaDataType')

    if groupID in gid_db:
        if msgHash in gid_db[groupID]['messageStore']:
            if pubKey in gid_db[groupID]['messageStore'][msgHash]['parties']:
                gid_db[groupID]['messageStore'][msgHash]['data'][mtaDataType].append(mtaData)
            else:
                return jsonify({}), 404
        else:
            return jsonify({}), 404
    else:
        return jsonify({}), 404
    
    return jsonify({}), 200

@app.route('/sign/mtaData', methods=['GET'])
def getMtaData():
    groupID = request.args.get('groupID')
    to = request.args.get('to')
    length = request.args.get('length')
    msgHash = request.args.get('msgHash')
    mtaDataType = request.args.get('mtaDataType')

    if groupID in gid_db:
        if msgHash in gid_db[groupID]['messageStore']:
            mtaDataList = [mtaData for mtaData in gid_db[groupID]['messageStore'][msgHash]['data'][mtaDataType] if mtaData['to'] == to]
            
            if len(mtaDataList) >= int(length):
                return jsonify(mtaDataList), 200
            else:
                return jsonify({}), 404
        else:
            return jsonify({}), 404
    else:
        return jsonify({}), 404

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")
