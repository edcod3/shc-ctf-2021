# For AES & Scrypt (pycryptodome / pycryptodomex)
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
# Base 64 decoding
from base64 import b64encode, b64decode
# Parsing json object
import json
# Get size in bytes
from sys import getsizeof
# Time Import
import time
from random import randint
from re import sub
# Logging & Websocket stuff
import urllib.parse
import websocket
import time
import logging

# logging.basicConfig(level=logging.DEBUG)
#logger = logging.getLogger(__name__)


def send(cmd="", url=""):
    cmd = str(cmd)
    ws = websocket.WebSocket()
    #logger.debug("command: {}".format(cmd))
    cmd = urllib.parse.quote(cmd)
    #logger.debug("encoded: {}".format(cmd))
    ws.connect(url.format(cmd))
    marker = "Data: "
    try:
        while ws.connected:
            line = ws.recv()
            #logger.debug("received: {}".format(line.encode()))
            if marker in line:
                return line[len(marker):]
    except:
        pass


def ws_cmd(cmd, url_id):
    url = "wss://" + url_id + ".idocker.vuln.land/api/deploy/task?argument={}"
    #Step 0: Websocket#
    data = send(cmd, url)
    # prints only "data"
    print(data)
    return data


##### En-/Decryption ###########

# Diffie-Hellman Key (int) to AES Key
def DH2AES(dh_key, salt, p):

    # Supposed AES Key Length
    AES_KEY_LEN = 16

    # Get Byte Array from DH Key
    key_bytes = dh_key.to_bytes((p.bit_length() + 7) // 8, "big")

    # Create AES Key from DH Key Array
    aes_enc_key = scrypt(key_bytes, salt, AES_KEY_LEN, N=2**14, r=8, p=1)

    return aes_enc_key


# AES decryption
def AESdecrypt(aes_enc_key, salt, p, nonce: bytes, ctxt: bytes, tag: bytes):
    ##aes_enc_key = DH2AES(dh_key, salt, p)
    cipher = AES.new(aes_enc_key, AES.MODE_GCM, nonce=nonce)
    #plaintext = cipher.decrypt_and_verify(ctxt, tag)
    plaintxt = cipher.decrypt(ctxt)
    print("--" * 30)
    print("Decoded: " + plaintxt.decode("utf-8"))
    print("--" * 30)
    try:
        verified = cipher.hexverify(tag.hex())
        print(verified)
    except KeyError as k_e:
        raise k_e
    except ValueError as v_e:
        raise v_e
    return plaintxt.decode("utf-8")


def AESencrypt(aes_enc_key, msg):
    cipher = AES.new(aes_enc_key, AES.MODE_GCM)
    ctxt = cipher.encrypt(msg.encode("utf-8"))
    tag = cipher.hexdigest()
    print("Message: " + msg)
    print("\n")
    enc = b64enc(cipher.nonce, ctxt, bytes.fromhex(tag))
    return enc

#####Base 64 Decoding ##########


# Convert base64 to integer
def decodeInt(val):
    decoded = int.from_bytes(b64decode(val), 'big')
    return decoded


# Convert base64 to String (utf-8)
def decodeStr(raw_str):
    decoded = b64decode(raw_str)
    return decoded.decode("utf-8")


####Get Values from JSON ########


def getVals1(json_raw):
    # Get JSON Data & parse to json
    json_data = json.loads(json_raw)

    # Decode from base64 to an integer
    g = decodeInt(json_data["g"])
    p = decodeInt(json_data["p"])
    decoded_phi = sub(r'(A)\1+', '', (json_data["phi"]))
    phi = decodeInt(decoded_phi)
    pubA = decodeInt(json_data["pubA"])
    salt = b64decode(json_data["salt"])

    return (g, p, phi, pubA, salt)


def getVals2(json_raw):
    # Get JSON Data & parse to json
    json_data = json.loads(json_raw)
    nonce = b64decode(json_data["nonce"])
    ctxt = b64decode(json_data["ctxt"])
    tag = b64decode(json_data["tag"])
    return (nonce, ctxt, tag)

##################


# Generate C from g, p & phi
def genDHwP(g, p, phi):
    phi_c = phi - 1
    c = 1
    cap_c = (g ** c) % p
    return (c, cap_c)


def gen1_DH(p, phi):
    #phi_c = phi - 1
    c = 1
    cap_c = 1 % p
    return (c, cap_c)


def b64newparams(json_raw, cap_a):
    cap_a_b64 = b64encode(cap_a.to_bytes(
        (cap_a.bit_length() + 7) // 8, byteorder="big")).decode("utf-8")
    parsed_json = json.loads(json_raw)
    json_k = ['g', 'p', 'phi', 'pubA', 'salt']
    json_v = [parsed_json['g'], parsed_json['p'],
              parsed_json['phi'], cap_a_b64, parsed_json['salt']]
    rslt = json.dumps(dict(zip(json_k, json_v)))
    return rslt

# b64 encrypt stuff


def b64enc(nonce, ctxt, tag):
    json_k = ['nonce', 'ctxt', 'tag']
    b64_nonce = b64encode(nonce).decode("utf-8")
    b64_ctxt = b64encode(ctxt).decode("utf-8")
    b64_tag = b64encode(tag).decode("utf-8")
    json_v = [b64_nonce, b64_ctxt, b64_tag]
    result = json.dumps(dict(zip(json_k, json_v)))
    return result


###########################


def Cap2Alice(key: int):
    key_bytes = key.to_bytes((key.bit_length() + 7) // 8, byteorder="big")
    encoded = b64encode(key_bytes).decode("utf-8")
    return '{"pubB": "' + encoded + '"}'


#### Flaw: The shared secret key will be 1 ######

def main():
    ## Step 0: Get ID of url ##
    url = input("URL id: ")
    ## Step 1: Generate keys ##
    ws_cmd("1", url)
    time.sleep(10)
    # Step 2: Intercept package (Alice 2 Bob) & Drop package
    alice_json = ws_cmd("1", url)
    ws_cmd("2", url)
    # Step 3: Get DH parameterws from Alice's message
    (g, p, phi, cap_a, salt) = getVals1(alice_json)
    (m2, cap_m2) = gen1_DH(p, phi)

    ## Step 4: Insert package with new pub key [1] & other DH Parameters to Bob ##
    ws_cmd("2", url)
    ws_cmd("Alice", url)
    ws_cmd("Bob", url)
    a2b = b64newparams(alice_json, cap_m2)
    ws_cmd(a2b, url)

    # Step 5: Intercept package (Bob 2 Alice)
    ws_cmd("1", url)

    # Step 6: Drop package (Bob 2 Alice)
    ws_cmd("2", url)

    # Step 7: Insert package with new key [1] (Bob 2 Alice)
    ws_cmd("2", url)
    ws_cmd("Bob", url)
    ws_cmd("Alice", url)
    json_pubB = Cap2Alice(1)
    ws_cmd(json_pubB, url)

    # Make AES Key from DH-Key [1]

    aes_enc_key = DH2AES(1, salt, p)

    # Check if message doesnt change
    decoded_list = []
    decoded_i = 0
    #Intercept Alice & Bob (Ask nicely for the key, she says)#
    while True:
        # Decrypt & drop message from Alice / Bob
        alice_msg1 = ws_cmd("1", url)
        ws_cmd("2", url)
        (nonce, ctxt, tag) = getVals2(alice_msg1)
        decoded = AESdecrypt(aes_enc_key, salt, p, nonce, ctxt, tag)
        decoded_list.append(decoded)
        if "Here is the flag:" in decoded:
            break
        if (decoded_i % 2 == 0):
            # Insert new values
            ws_cmd("2", url)
            ws_cmd("Alice", url)
            ws_cmd("Bob", url)
            encoded_msg = AESencrypt(
                aes_enc_key, decoded)
            ws_cmd(encoded_msg, url)
            decoded_i = decoded_i + 1
        else:
            # Insert new values
            ws_cmd("2", url)
            ws_cmd("Bob", url)
            ws_cmd("Alice", url)
            encoded_msg = AESencrypt(
                aes_enc_key, "Please")
            ws_cmd(encoded_msg, url)
            decoded_i = decoded_i + 1


if __name__ == "__main__":
    main()
