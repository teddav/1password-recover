import json
import binascii, base64

import dschuetz_oplib
import create_item

from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from jwkest.jwk import load_jwks

file = b""
with open("1password.sqlite", "rb") as f:
    byte = f.read(1)
    while byte != "":
        byte = f.read(1)
        file += byte
file = file.decode('utf-8','ignore').encode("utf-8").replace("\\","")

VAULT_NAME = raw_input("Vault name? (default: 'Private') ") or "Private"
print(VAULT_NAME)

# https://stackoverflow.com/a/55525704/5641484
def get_jsons(data):
    jsons = []
    right_indices = [i for i, c in enumerate(data) if c == '}']
    i = 0
    while i < len(data) - 1:
        if data[i] == '{':
            for j in right_indices:
                if i < j:
                    try:
                        parsed = json.loads(data[i: j + 1])
                        jsons.append(parsed)
                        i = j + 1
                        break
                    except Exception as e:
                        # print(e)
                        pass
        i += 1
    return jsons

def find_jsons(data, key, kid=""):
    key_index = data.find(key)
    jsons = []
    while key_index != -1:
        try:
            found = None
            end = 200
            while end < 4000:
                try:
                    found = get_jsons(data[key_index:key_index+end])[0]
                    break
                except:
                    end += 200
            
            if found:
                if kid:
                    if kid == found["kid"]:
                        jsons.append(found)
                else:
                    jsons.append(found)
        except Exception as e:
            # print(e)
            pass
        data = data[key_index + 1:]
        key_index = data.find(key)
    return jsons


def get_binary(data):
    try:
        bin = binascii.a2b_hex(data)
    except:
        try:
            bin = dschuetz_oplib.opb64d(data)
        except:
            try:
                bin = base64.b64decode(data)
            except:
                print("Unable to decode the input. Enter in hex or base64.")
                exit(1)
    return bin

def get_2sdk(data):
    enc_sym_key_index = data.find('enc_sym_key')
    enc_sym_keys = filter(lambda x: "p2s" in x, find_jsons(data[enc_sym_key_index:], "enc_sym_key"))

    secret_key = raw_input("\nEnter the account's Secret Key (A3-xxx....): ").upper()
    password = raw_input("\nEnter the master password: ")
    email = raw_input("\nEnter the email address: ")

    for enc_sym_key in enc_sym_keys:
        p2s = get_binary(enc_sym_key["p2s"].encode("utf-8"))
        p2c = int(enc_sym_key["p2c"])
        algo = enc_sym_key["alg"].encode("utf-8")

        try:
            muk = dschuetz_oplib.opb64e(dschuetz_oplib.compute_2skd(secret_key, password, email, p2s, p2c, algo))
            mk = json.loads(gcm_decrypt(muk, enc_sym_key["iv"].encode("utf-8"), enc_sym_key["data"].encode("utf-8")))
            return (muk, mk)
        except:
            print('error')

    raise Exception("couldnt compute MUK and MK")

def gcm_decrypt(key, iv, cipher):
    key = get_binary(key)
    iv = get_binary(iv)
    ct = get_binary(cipher)
    return dschuetz_oplib.dec_aes_gcm(ct[:-16], key, iv, ct[-16:])

def rsa_decrypt(key, _cipher):
    jwkj = '{"keys": [%s]}' % key
    jwk = json.loads(jwkj)
    jwk = load_jwks(jwkj)[0]
    RSA_Key = RSA.construct((jwk.n, jwk.e, jwk.d))

    ct = get_binary(_cipher)
    cipher = PKCS1_OAEP.new(RSA_Key)
    return json.loads(cipher.decrypt(ct))

(muk, mk) = get_2sdk(file)
# print("MUK ->\n", muk)
# print("MK ->\n", mk)

enc_pri_keys = find_jsons(file, "enc_pri_key")
# print("enc_pri_keys", enc_pri_keys)
enc_pri_key = list(filter(lambda x: x["kid"] == mk["kid"], enc_pri_keys))[0]
# print("enc_pri_key", enc_pri_key)
rsa = gcm_decrypt(mk["k"].encode("utf-8"), enc_pri_key["iv"].encode("utf-8"), enc_pri_key["data"].encode("utf-8"))
# print("RSA ->\n", rsa)

vault_keys = list(map(lambda x: rsa_decrypt(rsa, x["data"].encode("utf-8")), find_jsons(file, "enc_vault_key", mk["kid"].encode("utf-8"))))
print("vault_keys", vault_keys)
for vault_key in vault_keys:
    # print("VAULT KEY", vault_key)
    enc_attrs = find_jsons(file, "enc_attrs", vault_key["kid"].encode("utf-8"))[0]
    vault = json.loads(gcm_decrypt(vault_key["k"].encode("utf-8"), enc_attrs["iv"].encode("utf-8"), enc_attrs["data"].encode("utf-8")))
    print("VAULT: ", vault)

    if vault["name"] != VAULT_NAME:
        continue

    items = list(filter(lambda x: "kid" in x and x["kid"] == vault_key["kid"], get_jsons(file)))
    for item in items:
        password = gcm_decrypt(vault_key["k"].encode("utf-8"), item["iv"].encode("utf-8"), item["data"].encode("utf-8"))
        print(password)
        # create_item.create_item()

# def loop_json(obj, key_to_find="", value_to_find=""):
#     for key,value in obj.items():
#         if key == key_to_find:
#             if value == value_to_find or value == "":
#                 return obj
#         if value == value_to_find and key == "":
#             return obj
        
#         if type(value) == type(dict()):
#             return loop_json(value, key_to_find, value_to_find)
#         elif type(value) == type(list()):
#             pass