#!/usr/bin/env python
#
# Code related to ESET's Stantinko research.
# This script decrypts AdStantinko communication. It expects base64 encoded data.
# The magic header for AdStantinko communication is "KK".
# If once decoded the data begins with "KK", it is likely this script will decrypt it.
# Communication with "clients{1,2,3}.ultimate-discounter.com" uses this encryption algorithm.
#
# For feedback or questions contact us at: github@eset.com
# https://github.com/eset/malware-research/
# Frederic Vachon <frederic.vachon@eset.com>
#
# This code is provided to the community under the two-clause BSD license as
# follows:
#
# Copyright (C) 2017 ESET
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from __future__ import unicode_literals
from __future__ import print_function

import argparse
import base64
import os
import struct
import sys

from Crypto.Cipher import ARC4
from Crypto.Hash import MD5, SHA256


def decrypt(data, key):
    key_ = MD5.new(key).hexdigest()
    cipher = ARC4.new(key_)
    return cipher.decrypt(data)


def decode_key(data):
    i_tab = [7, 4, 0, 8, 3, 2, 5, 9, 6, 1]
    tick = [''] * 10

    for i, b in enumerate(data):
        tick[i_tab[i]] = b

    key = ""
    key_indexes = [7, 6, 7, 8, 5, 9]

    for i in key_indexes:
        key += tick[i]

    return key


def extract_payload_from_file(filename):
    with open(filename, "rb") as f:
        data = f.read()

    try:
        data = base64.b64decode(data)
    except TypeError:
        return ''

    if not len(data) > 7:
        return ''

    if data[:2] != 'KK':
        return ''

    encoded_tick = ''.join([str(struct.unpack('<b', b)[0]).rjust(2, b'0') for b in data[2:7]])
    key = decode_key(encoded_tick)

    return decrypt(data[7:], key)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract AdStantinko payloads")
    parser.add_argument("-i", "--input", help="Input directory",
                        metavar="filename", required=True)
    parser.add_argument("-o", "--output", help="Output directory",
                        metavar="filename", required=False)
    args = parser.parse_args()

    payload = extract_payload_from_file(args.input)

    if len(payload) < 1:
        print("ERROR : Invalid payload", file=sys.stderr)

    if args.output is not None:
        with open(args.output, "wb") as f:
            f.write(payload)
    else:
        sys.stdout.write(payload)
