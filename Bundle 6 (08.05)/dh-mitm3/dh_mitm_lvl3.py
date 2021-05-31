# For AES & Scrypt (pycryptodome / pycryptodomex)
from Crypto.Util.number import *
from Crypto.Protocol.KDF import scrypt
from Crypto.Cipher import AES
# Base 64 decoding
from base64 import b64encode, b64decode
# Parsing json object
import json
# Time Import
import time
# Logging & Websocket stuff
import urllib.parse
import websocket
import time
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


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


def sendReload(url=""):
    ws = websocket.WebSocket()
    ws.connect(url)
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
    # print(data)
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
    # aes_enc_key = DH2AES(dh_key, salt, p)
    cipher = AES.new(aes_enc_key, AES.MODE_GCM, nonce=nonce)
    # plaintext = cipher.decrypt_and_verify(ctxt, tag)
    plaintxt = cipher.decrypt(ctxt)
    #print("--" * 30)
    #print("Decoded: " + plaintxt.decode("utf-8"))
    #print("--" * 30)
    try:
        verified = cipher.hexverify(tag.hex())
        # print(verified)
    except KeyError as k_e:
        raise k_e
    except ValueError as v_e:
        raise v_e
    return plaintxt.decode("utf-8")


def AESencrypt(aes_enc_key, msg):
    cipher = AES.new(aes_enc_key, AES.MODE_GCM)
    ctxt = cipher.encrypt(msg.encode("utf-8"))
    tag = cipher.hexdigest()
    #print("Message: " + msg)
    # print("\n")
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
    phi = decodeInt(json_data["phi"])
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


def getVals3(json_raw):
    # Get JSON Data & parse to json
    json_data = json.loads(json_raw)

    # Decode from base64 to an integer
    pubB = decodeInt(json_data["pubB"])

    return pubB

##################


def getFactors(j, p, limit=False):
    #print("Factorizing:", j)
    small_factors = []
    i = 3
    lim = j
    if limit != False:
        lim = limit
    while i <= lim:
        if j % i == 0 and (p - 1) % i == 0:
            # print(i)
            small_factors.append(i)
            if (p - 1) % (i * i) == 0:
                small_factors.append(i * i)
            j = j // i
            i = i + 1
            continue
        else:
            i = i + 1
            continue
    return small_factors


def getGenerator(p, g, factors):
    for factor in factors:
        l = (p - 1) // factor
        chk = pow(g, l, p)
        if chk != 1:
            #print("Found generator:", chk)
            #print("Order of generator:", factor)
            return factor, chk, l
        else:
            continue
    return None, None, None


def SSGCA(json_raw, phi, p, g, pub_a):
    """
    The Attack: Small Subgroup Confinement with generating gi as subgroup of order qi. 
    Get the Response from Bob and calculate the shared key with the help of the Polland Rho Algorithm.

    phi = p - 1
    qi is factor of phi
    g = gi = g ** ((p - 1) / qi)
    (p - 1) % qi == 0 (qi is factor of (p -1) & phi) 
    """

    R = (p - 1) // phi

    factors = getFactors(R, p, limit=R)
    order, new_gen, q = getGenerator(p, g, factors)
    if len(factors) == 0 or q == None:
        factors = getFactors(phi, p, limit=2 ** 26)
        order, new_gen, q = getGenerator(p, g, factors)
    phi = phi
    pubA = pow(pub_a, q, p)

    phi_b64 = b64encode(phi.to_bytes(
        (phi.bit_length() + 7) // 8, byteorder="big")).decode("utf-8")
    g_b64 = b64encode(g.to_bytes((g.bit_length() + 7) //
                                 8, byteorder="big")).decode("utf-8")
    g_b64 = b64encode(new_gen.to_bytes((new_gen.bit_length() + 7) //
                                       8, byteorder="big")).decode("utf-8")
    p_b64 = b64encode(p.to_bytes((p.bit_length() + 7) //
                                 8, byteorder="big")).decode("utf-8")
    pubA_b64 = b64encode(pubA.to_bytes(
        (pubA.bit_length() + 7) // 8, byteorder="big")).decode("utf-8")
    parsed_json = json.loads(json_raw)
    json_k = ['g', 'p', 'phi', 'pubA', 'salt']
    json_v = [g_b64, p_b64,
              phi_b64, pubA_b64, parsed_json['salt']]
    rslt = json.dumps(dict(zip(json_k, json_v)))
    return (rslt, q, order, new_gen, pubA)

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


# Get Key with Polland Rho Algorithm to solve the DLP #
# Source for Polland-Rho Algorithm: https://github.com/ashutosh1206/Crypton/blob/master/Discrete-Logarithm-Problem/Algo-Pollard-Rho/pollardrho.py

def func_f(x_i, base, y, p):
    """
    x_(i+1) = func_f(x_i)
    """
    if x_i % 3 == 2:
        return (y*x_i) % p
    elif x_i % 3 == 0:
        return pow(x_i, 2, p)
    elif x_i % 3 == 1:
        return base*x_i % p
    else:
        print("[-] Something's wrong!")
        return -1


def func_g(a, n, p, x_i):
    """
    a_(i+1) = func_g(a_i, x_i)
    """
    if x_i % 3 == 2:
        return a
    elif x_i % 3 == 0:
        return 2*a % n
    elif x_i % 3 == 1:
        return (a + 1) % n
    else:
        print("[-] Something's wrong!")
        return -1


def func_h(b, n, p, x_i):
    """
    b_(i+1) = func_g(b_i, x_i)
    """
    if x_i % 3 == 2:
        return (b + 1) % n
    elif x_i % 3 == 0:
        return 2*b % n
    elif x_i % 3 == 1:
        return b
    else:
        print("[-] Something's wrong!")
        return -1


def pollardrho(base, y, p, n):
    """
    Refer to section 3.6.3 of Handbook of Applied Cryptography
    Computes `x` = a mod n for the DLP base**x % p == y
    in the Group G = {0, 1, 2, ..., n}
    given that order `n` is a prime number.
    :parameters:
        base : int/long
                Generator of the group
        y : int/long
                Result of base**x % p
        p : int/long
                Group over which DLP is generated.
        n : int/long
                Order of the group generated by `base`.
                Should be prime for this implementation
    """

    if not isPrime(n):
        print("[-] Order of group must be prime for Pollard Rho")
        return -1

    x_i = 1
    x_2i = 1

    a_i = 0
    b_i = 0
    a_2i = 0
    b_2i = 0

    i = 1
    while i <= n:
        # Single Step calculations
        a_i = func_g(a_i, n, p, x_i)
        b_i = func_h(b_i, n, p, x_i)
        x_i = func_f(x_i, base, y, p)

        # Double Step calculations
        a_2i = func_g(func_g(a_2i, n, p, x_2i), n, p, func_f(x_2i, base, y, p))
        b_2i = func_h(func_h(b_2i, n, p, x_2i), n, p, func_f(x_2i, base, y, p))
        x_2i = func_f(func_f(x_2i, base, y, p), base, y, p)

        if x_i == x_2i:
            """
            If x_i == x_2i is True
            ==> (base^(a_i))*(y^(b_i)) = (base^(a_2i))*(y^(b_2i)) (mod p)
            ==> y^(b_i - b_2i) = base^(a_2i - a_i)                (mod p)
            ==> base^((b_i - b_2i)*x) = base^(a_2i - a_i)         (mod p)
            ==> (b_i - b_2i)*x = (a_2i - a_i)                     (mod n)
            r = (b_i - b_2i) % n
            if GCD(r, n) == 1 then,
            ==> x = (r^(-1))*(a_2i - a_i)                         (mod n)
            """
            r = (b_i - b_2i) % n
            if r == 0:
                print("[-] b_i = b_2i, returning -1")
                return -1
            else:
                assert GCD(r, n) == 1
                """
                If `n` is not a prime number this algorithm will not be able to
                solve the DLP, because GCD(r, n) != 1 then and one will have to
                write an implementation to solve the equation:
                    (b_i - b_2i)*x = (a_2i - a_i) (mod n)
                This equation will have multiple solutions out of which only one
                will be the actual solution
                """
                return (inverse(r, n)*(a_2i - a_i)) % n
        else:
            i += 1
            continue


def getKey(gen, pubB, p, order, A_modified):
    guess_b = pollardrho(gen, pubB, p, order)
    guess_keyB = pow(A_modified, guess_b, p)
    return guess_keyB


#### Flaw: Small Subgroup Confinement Attack ######


def main():
    ## Step 0: Get ID of url ##
    url = input("URL id: ")
    ## Step 0.1: Reload Challenge ##
    sendReload("wss://" + url + ".idocker.vuln.land/api/deploy/")
    time.sleep(3)
    ## Step 1: Generate keys ##
    ws_cmd("1", url)
    time.sleep(10)
    # Step 2: Intercept package (Alice 2 Bob) & Drop package
    alice_json = ws_cmd("1", url)
    ws_cmd("2", url)
    # Step 3: Get DH parameterws from Alice's message
    (g, p, phi, cap_a, salt) = getVals1(alice_json)
    ## Step 4: Insert package with new pub key & generator along with other DH Parameters to Bob ##
    ws_cmd("2", url)
    ws_cmd("Alice", url)
    ws_cmd("Bob", url)
    # Most of the calculations for the Small Subgroup Confinement Attack are done here
    (a2b, q, order, new_gen, A_modified) = SSGCA(alice_json, phi, p, g, cap_a)
    ws_cmd(a2b, url)

    # Step 5: Intercept package (Bob 2 Alice)
    bob = ws_cmd("1", url)
    cap_b = getVals3(bob)
    # Get Key with the help of Polland Rho from the response of Bob
    shared_key = getKey(new_gen, cap_b, p, order, A_modified)
    # Step 6: Drop package (Bob 2 Alice)
    ws_cmd("2", url)

    # Step 7: Send received key (from Bob) to Alice (Bob 2 Alice)
    ws_cmd("2", url)
    ws_cmd("Bob", url)
    ws_cmd("Alice", url)
    json_pubB = Cap2Alice(cap_b)
    ws_cmd(json_pubB, url)

    # Make AES Key from DH-Key [1]
    aes_enc_key = DH2AES(shared_key, salt, p)

    decoded_i = 0
    #Intercept Alice & Bob X as spaces are used to send all characters & skip over response iteritation #
    printable = "XX-XaXbXcXdXeXfX0X1X2X3X4X5X6X7X8X9Z"
    for character in printable:
        # Decrypt & drop message from Alice / Bob
        alice_msg1 = ws_cmd("1", url)
        ws_cmd("2", url)
        (nonce, ctxt, tag) = getVals2(alice_msg1)
        decoded = AESdecrypt(aes_enc_key, salt, p, nonce, ctxt, tag)
        if character == "Z":
            print(decoded)
        if (decoded_i % 2 == 0):
            # Insert new values
            ws_cmd("2", url)
            ws_cmd("Alice", url)
            ws_cmd("Bob", url)
            encoded_msg = AESencrypt(
                aes_enc_key, "Does the flag contain a '"+character+"'?")
            ws_cmd(encoded_msg, url)
            decoded_i = decoded_i + 1
        else:
            # Insert new values
            ws_cmd("2", url)
            ws_cmd("Bob", url)
            ws_cmd("Alice", url)
            encoded_msg = AESencrypt(
                aes_enc_key, decoded)
            ws_cmd(encoded_msg, url)
            decoded_i = decoded_i + 1


if __name__ == "__main__":
    main()
