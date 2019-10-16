#!/usr/bin/env python3
#
# This script decrypts PolyglotDuke's C&C URL found in public posts from
# twitter, imgur, reddit etc.
#
# For feedback or questions contact us at: github@eset.com
# https://github.com/eset/malware-research/
#
# This code is provided to the community under the two-clause BSD license as
# follows:
#
# Copyright (C) 2019 ESET
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

import sys
import re


def is_url(string):
    match = re.match(r"(?m)^(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$", string)
    return match is not None


def to_byte(encrypted_cnc):
    buf = []
    if encrypted_cnc[0] < 0xe0 or encrypted_cnc[0] > 0xef:
        if encrypted_cnc[0] < 0xc2 or encrypted_cnc[0] > 0xdf:
            return None
        buf_length = len(encrypted_cnc)/2
        for i in range(buf_length):
            val = ((0xffff & (encrypted_cnc[i*2] >> 2) & 7) << 8) | (0xffff & encrypted_cnc[i*2] << 6) | (encrypted_cnc[i*2+1] & 0x3f)
            buf.append(val)
    else:
        buf_length = int(len(encrypted_cnc)/3)
        for i in range(buf_length):
            val = 0xff & (((((encrypted_cnc[i*3+1] & 0x3F) >> 2) | (16 * encrypted_cnc[i*3])) << 8) | (((encrypted_cnc[i*3+1] & 0x3F) << 6) | encrypted_cnc[i*3+2] & 0x3F))
            buf.append(val)
    return buf


def transpose_to_ascii(buf, offset_array, wide_char_key):
    str_len = len(buf)
    key_len = len(wide_char_key)

    if str_len <= 0:
        return ""

    transposed = []
    for i in range(str_len):
        for offset_itr in range(key_len):
            if buf[i] == offset_array[offset_itr]:
                transposed.append(wide_char_key[offset_itr])
                break

    transposed_str = [chr(char) for char in transposed]
    return transposed_str


def decrypt_domain(buf, key_str):
    clear = []
    try:
        for i, char in enumerate(buf):
            idx = key_str.index(char)
            new_idx = idx + 71*(int(i/71)+1) - i
            clear.append(key_str[9*new_idx % 71])
    except ValueError:
        clear = []
    clear_str = ''.join(clear)
    clear_str_rev = clear_str[::-1]
    return clear_str_rev


def decrypt_cnc(encrypted_cnc):
    key_str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./?&=_-#%"

    wide_char_key = [ord(i) & 0xffff for i in key_str]

    # offset arrays change between samples thus we are checking for decrypted URL with
    # a wide range of offset arrays.
    for i in range(500):
        offset_array = [j for j in range(i, i+len(wide_char_key))]

        int8_buf = to_byte(encrypted_cnc)
        transposed = transpose_to_ascii(int8_buf, offset_array, wide_char_key)
        decrypted_domain = decrypt_domain(transposed, key_str)

        if decrypted_domain and is_url(decrypted_domain):
            print(decrypted_domain)


def main(argv):
    if len(argv) < 2:
        print("Usage:\n", argv[0], "[encryptedCNC]")
        return

    print(argv[1])
    encrypted_cnc = bytes(argv[1], 'UTF-8')
    decrypt_cnc(encrypted_cnc)


if __name__ == "__main__":
    main(sys.argv)
