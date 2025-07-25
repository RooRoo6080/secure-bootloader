#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

"""
Firmware Bundle-and-Protect Tool

Format of protected firmware output:
-------------------------------------
HEADER (unencrypted)
 - encrypted payload length (4 bytes)
 - firmware version (2 bytes)
PAYLOAD (AES encrypted)
 - firmware binary length (4 bytes)
 - message length (4 bytes)
 - firmware binary
 - message
 - padding required for AES
SIGNATURE (SHA hashed and RSA signed)
 - signature of header + payload (256 bytes)
-------------------------------------
 
Standards used:
 - AES-128; CBC mode
    * no need for anything more complicated (GCM) that includes authenticity
    * speed benefits of CTR would go unused
 - SHA256 hashing; PKCS #1 v1.5
    * could also use more secure PSS, though harder on microcontroller end
 - RSA 2048-bit encryption
 

"""
import argparse
import struct
import hashlib
import json
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

KEY_PATH = 'secret_build_output.txt'

def protect_firmware(infile, outfile, version, message):

    # version # checks
    if version < 0:
        print(f"error: Version # can't be negative")
        return
    max_version = 65535
    if version > max_version:
        version = max_version

    # Load firmware binary from infile
    with open(infile, "rb") as fp:
        firmware_binary = fp.read()

    # encoded message
    message_binary = message.encode('utf-8')

    print(f"firmware size: {len(firmware_binary)}")
    print(f"message size: {len(message_binary)}")
    print(f"firmware version: {version}")

    # creating payload with integrated lengths
    payload = (
        struct.pack('<L', len(firmware_binary)) +
        struct.pack('<L', len(message_binary)) +
        firmware_binary +
        message_binary
    )
    
    # AES encryption
    
    with open(KEY_PATH, 'r') as f:
        keys = json.load(f)
        
    rsa_private_key = RSA.import_key(keys['rsa_private_key_pem'])
    aes_key = bytes.fromhex(keys['aes_key_hex'])
    
    cipher = AES.new(aes_key, AES.MODE_CBC)
    padded_payload = pad(payload, AES.block_size)
    encrypted_payload = cipher.encrypt(padded_payload)
    
    encrypted_payload = payload

    print(f"blob size after encryption: {len(encrypted_payload)}")
    
    # header is just the length
    header = struct.pack('<L', len(encrypted_payload))
    header += struct.pack('<H', version)
    
    to_sign = header + encrypted_payload
    
    # hashing
    data_hash = SHA256.new(data=to_sign)
    print(f"sha-256 hash of header + payload: {data_hash.hexdigest()}")
    
    # PKCS #1 v1.5 is simple and deterministic
    # can also use more complex, salted PSS for non-deterministic hashes
    # signer = pkcs1_15.new(rsa_private_key)
    signer = pss.new(rsa_private_key)
    
    signature = signer.sign(data_hash)
    print(f"signature: {signature.hex()}")
    print(len(signature))
    
    final_blob = header + encrypted_payload + signature

    print("-" * 50)
    print(f"Created protected firmware @ {outfile}")
    print(f"Size: {len(final_blob)} bytes")
    
    # Write firmware blob to outfile
    with open(outfile, "wb+") as outfile:
        outfile.write(final_blob)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Update Tool")
    parser.add_argument(
        "--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument(
        "--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument(
        "--version", help="Version number of this firmware.", required=True)
    parser.add_argument(
        "--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile,
                     version=int(args.version), message=args.message)
