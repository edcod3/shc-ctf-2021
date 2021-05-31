import hashlib


backdoor_hash = ["0x45", "0xD6", "0x16", "0xFF", "0x7D", "0x51", "0x08",
                 "0xBD", "0x93", "0x09", "0x4F", "0xA1", "0x5F", "0xE0", "0xE1", "0xD2"]

backdoor_hash1 = "".join([x.replace("0x", "").lower() for x in backdoor_hash])


def domd5hash(string):
    md5_hash = hashlib.md5(string.encode())
    return md5_hash.hexdigest()


def main():
    for i in range(10000):
        pin = "{0:04d}".format(i)
        md5_inp = "HL{" + str(pin) + "}"
        md5 = domd5hash(md5_inp)
        if md5 == backdoor_hash1:
            print("Flag: " + md5_inp)
            break
        else:
            continue


if __name__ == "__main__":
    main()
