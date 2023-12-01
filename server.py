from flask import Flask, request, jsonify
import hashlib
import json

app = Flask(__name__)

# This is the key-value storage for the fingerprints and associated data
fp_to_entity_info = {}
pub_to_gid = {}
gid_db = {}


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

@app.route('/entityInfo', methods=['GET'])
def getEntityInfo():
    fingerprint = request.args.get('fingerprint')
    return jsonify(fp_to_entity_info.get(fingerprint, '')), 200

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
        gid_db[groupID] = {'groupInfo': groupInfo, 'signatures': {pubKey: signature}, 'shares': {}}

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


# route to get group ids from pub key
@app.route('/groupID', methods=['GET'])
def getGroupID():
    pubKey = request.args.get('pubKey')
    return jsonify(pub_to_gid.get(pubKey, [])), 200

if __name__ == '__main__':
    app.run(debug=True)
