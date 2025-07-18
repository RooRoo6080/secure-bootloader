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
from Crypto.PublicKey import RSA

REPO_ROOT = pathlib.Path(__file__).parent.parent.absolute()
BOOTLOADER_DIR = os.path.join(REPO_ROOT, "bootloader")
SECRET_BUILD_OUTPUT_PATH = os.path.join(pathlib.Path(
    __file__).parent.absolute(), "secret_build_output.txt")
PUBLIC_KEY_C_FILE_PATH = os.path.join(BOOTLOADER_DIR, "inc", "public_key.h")


def make_bootloader() -> bool:
    # Build the bootloader from source.

    os.chdir(BOOTLOADER_DIR)

    subprocess.call("make clean", shell=True)
    status = subprocess.call("make")

    # Return True if make returned 0, otherwise return False.
    return status == 0


def generate_rsa_keys(public_key_output_path, private_key_output_path):
    print("Generating RSA key pair...")
    key = RSA.generate(2048)

    with open(private_key_output_path, "wb") as f:
        f.write(key.export_key())
    print(f"RSA Private Key saved to: {private_key_output_path}")

    public_key_der = key.publickey().export_key('DER')

    with open(public_key_output_path, "w") as f:
        f.write("#ifndef PUBLIC_KEY_H\n")
        f.write("#define PUBLIC_KEY_H\n\n")
        f.write("#include <stdint.h>\n\n")
        f.write(f"const uint8_t public_key_der[] = {{\n    ")
        f.write(", ".join(f"0x{b:02x}" for b in public_key_der))
        f.write("\n};\n")
        f.write(
            f"const uint32_t public_key_der_len = {len(public_key_der)};\n\n")
        f.write("#endif // PUBLIC_KEY_H\n")
    print(
        f"RSA Public Key (DER byte array) saved to: {public_key_output_path}")


if __name__ == "__main__":
    generate_rsa_keys(PUBLIC_KEY_C_FILE_PATH, SECRET_BUILD_OUTPUT_PATH)
    
    if make_bootloader():
        print("bl_build succeeded")
    else:
        print("bl_build failed")