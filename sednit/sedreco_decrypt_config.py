#!/usr/bin/env python
#
# Code related to ESET's research on the Sednit group.
# For feedback or questions contact us at: github@eset.com
# https://github.com/eset/malware-research/
# Jessy Campos <campos@esetlabs.com>
#
# This code is provided to the community under the two-clause BSD license as
# follows:
#
# Copyright (C) 2016 ESET
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
#

import argparse
import binascii
import struct
import sys


def decrypt(data, data_size, key):
    out = ""
    i = 0
    key_size = len(key)
    while i < (data_size / 6):
        if i == key_size / 6:
            idx = key_size % 6
        else:
            idx = 0
        for j in range(idx, 6):
            tmp = ord(data[6 * i + j]) ^ \
                  ((ord(key[(j + 3) % 6]) ^ (j + 6 * i)) & ord(key[(j + 2) % 6])) + \
                  (ord(key[(j + 1) % 6]) ^ (ord(key[j]) * (j + 6 * i) >> 7))
            tmp &= 0xFF
            out += chr(tmp)
        i += 1

    if i == key_size / 6:
        idx2 = key_size % 6
    else:
        idx2 = 0
    k = idx2
    while k < (data_size % 6):
        tmp = ord(data[6 * i + k]) ^ \
                ((ord(key[(k + 3) % 6]) ^ (k + 6 * i)) & ord(key[(k + 2) % 6])) + \
                (ord(key[(k + 1) % 6]) ^ (ord(key[k]) * (k + 6 * i) >> 7))
        tmp &= 0xFF
        out += chr(tmp)
        k += 1
    return out


def decrypt_msd_file(f):
    """
    Print the decrypted content of the configuration file.
    - in: an opened "msd" file.
    """
    key = f.read(6)
    data_size = struct.unpack('B' * 20, f.read(20))
    data = f.read()
    total_size = 0
    struct_format = ""
    for entry_size in data_size:
        # building the struct format used later
        struct_format += "{}s ".format(entry_size)
        total_size += entry_size
    return struct.unpack(struct_format, decrypt(data, total_size, key))


def decrypt_config_string(string):
    """
    Print the decrypted content of the given string.
    - in: The hexadecimal string representing the encrypted configuration.
    """
    import StringIO
    return decrypt_msd_file(StringIO.StringIO(string))

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--msd', metavar="PATH",
                             help="Decrypt the specified msd file")
    input_group.add_argument('--decode-string', metavar="CONFIGSTRING",
                             help="Decrypt the given string")

    args = parser.parse_args()

    if args.decode_string:
        print(decrypt_config_string(binascii.unhexlify(args.decode_string)))

    if args.msd:
        with open(args.msd, "rb") as f:
            print(decrypt_msd_file(f))
