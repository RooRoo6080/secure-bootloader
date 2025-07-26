#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

"""
Bootloader Build Tool

This tool is responsible for building the bootloader from source and copying
the build outputs into the host tools directory for programming.
"""
import os
import pathlib
import subprocess
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

REPO_ROOT = pathlib.Path(__file__).parent.parent.absolute()
BOOTLOADER_DIR = os.path.join(REPO_ROOT, "bootloader")
SECRET_BUILD_OUTPUT_PATH = "secret_build_output.txt"
PUBLIC_KEY_C_FILE_PATH = os.path.join(BOOTLOADER_DIR, "inc", "public_key.h")


def make_bootloader() -> bool:
    # Build the bootloader from source.

    os.chdir(BOOTLOADER_DIR)

    subprocess.call("make clean", shell=True)
    status = subprocess.call("make")

    # Return True if make returned 0, otherwise return False.
    return status == 0


def generate_rsa_keys(public_key_c_path, secret_keys_json_path):

    # creating RSA keys
    rsa_key = RSA.generate(2048)
    rsa_private_key_pem = rsa_key.export_key('PEM').decode('utf-8')
    rsa_public_key_der = rsa_key.publickey().export_key('DER')

    # creating AES key
    aes_key_hex = get_random_bytes(16)
    cipher = AES.new(aes_key_hex, AES.MODE_CBC)
    iv = cipher.iv

    # storing both RSA private and AES keys in JSON for fw_protect
    secret_keys = {
        "rsa_private_key_pem": rsa_private_key_pem,
        "aes_key_hex": aes_key_hex.hex(),
        "aes_iv": iv.hex()
    }
    with open(secret_keys_json_path, "w") as f:
        json.dump(secret_keys, f, indent=4)
    print(
        f"RSA private key and AES key saved as json to {secret_keys_json_path}")

    # saving AES key under bootloader/inc/public_key.h header file for bootloader program
    with open(public_key_c_path, "w") as f:
        f.write("#define PUBLIC_KEY_H\n")
        f.write("#include <stdint.h>\n\n")
        f.write("const uint8_t public_key_der[] = {" + ", ".join(
            f"0x{b:02x}" for b in rsa_public_key_der) + "};\n")
        f.write("const byte aes_key[16] = {" + ", ".join(
            f"0x{b:02x}" for b in bytes.fromhex(aes_key_hex.hex())) + "};\n")
        f.write("const byte aes_iv[] = {" + ", ".join(
            f"0x{b:02x}" for b in iv) + "};\n")


if __name__ == "__main__":
    generate_rsa_keys(PUBLIC_KEY_C_FILE_PATH, SECRET_BUILD_OUTPUT_PATH)

    if make_bootloader():
        print("bl_build succeeded")
    else:
        print("bl_build failed")
