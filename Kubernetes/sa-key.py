#!/usr/bin/env python3

"""
{
  "alg": "RS256"
}
{
  "aud": [
    "https://kubernetes.default.svc.<node-name>" # cluster.local or xxx
  ],
  "exp": 1735799999,
  "iat": 1704164933,
  "iss": "https://kubernetes.default.svc.<node-name>",
  "kubernetes.io": {
    "namespace": "<ns>",
    "serviceaccount": {
      "name": "<name>",
      "uid": "<sa-uid>"
    }
  },
  "nbf": 1704164933,
  "sub": "system:serviceaccount:<ns>:<name>"
}
"""

import jwt
import time
import logging
import argparse
import requests

logging.basicConfig(format="%(asctime)s - %(message)s", level=logging.INFO)
PROXIES = {}


def get_private_key(filename):
    with open(filename, "rb") as key_file:
        private_key = key_file.read()
    return private_key


def get_public_key(filename):
    with open(filename, "rb") as key_file:
        public_key = key_file.read()
    return public_key


def sign_time():
    t = int(time.time())
    return t

def get_token(private_key, namespace, node_name, uid, serviceaccount, extra_nodes=[]):
    full_nodes = [f"https://kubernetes.default.svc.{node_name}"]
    for node in extra_nodes:
        full_nodes.append(node)
    payload = \
        {
            "aud": full_nodes,
            "exp": sign_time() + 100000,
            "iat": sign_time() - 100000,
            "iss": f"https://kubernetes.default.svc.{node_name}",
            "kubernetes.io": {
                "namespace": f"{namespace}",
                "serviceaccount": {
                    "name": f"{serviceaccount}",
                    "uid": f"{uid}",
                },
            },
            "nbf": sign_time() - 100000,
            "sub": f"system:serviceaccount:{namespace}:{serviceaccount}",
        }
    logging.debug(f"Payload: {payload}")
    token = jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
    )
    logging.debug(f"Token: {token}")
    return token

def _parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-k", metavar="key", required=True, help="The private key file")
    parser.add_argument(
        "-s", metavar="service account name", default="default", help="Default: default"
    )
    parser.add_argument(
        "-n", metavar="namespace", default="kube-system", help="Default: kube-system"
    )
    parser.add_argument(
        "-u", metavar="uid", help="UserID for the sa", required=True,
    )
    parser.add_argument(
        "-m", metavar="node name", help="The node name", required=True,
    )
    parser.add_argument(
        "-e", metavar="extra nodes", default=[], help="Default: []",nargs='*',
    )
    parser.add_argument(
        "-t",
        metavar="target_url",
        help="Please keep the trailing slash, example: https://xxxx:6443/",
        required=False,
    )
    return parser.parse_args()

def main():
    args = _parse_args()
    private_key = get_private_key(args.k)

    token = get_token(
        private_key,
        args.n, # namespace
        args.m, # node name
        args.u, # uid
        args.s, # service account name
        args.e, # extra nodes
    )
    logging.info(f"Token: {token}")

    if (args.t):
        if not args.t.endswith("/"):
            args.t = args.t + "/"
        requests.packages.urllib3.disable_warnings()
        req = requests.get(
            f"{args.t}version",
            proxies=PROXIES,
            verify=False,
            headers={"Authorization": f"Bearer {token}"},
        )

        logging.debug(req.text)
        if req.status_code != 200:
            logging.info("Token is valid")
            return
        logging.info(req.json())

if __name__ == "__main__":
    main()