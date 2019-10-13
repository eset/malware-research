# -*- encoding: utf-8 -*-
#
# This script unpacks the payload from Winnti Group samples using their custom
# packer. For details, see:
# https://www.welivesecurity.com/wp-content/uploads/2019/10/ESET_Winnti.pdf
#
# For feedback or questions contact us at: github@eset.com
# https://github.com/eset/malware-research/
#
# Author:
# Marc-Etienne M.Léveillé <leveille@eset.com>
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
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import sys
import os
import struct
from Crypto.Cipher import ARC4
import hashlib
import json

# Those are the last functions of the shellcode returning the address of the
# payload header (minus 3)
GET_PAYLOAD_FUNCTIONS = [
    # 32-bit
    "558BECE800000000585DC3".decode('hex'),
    # 64-bit
    "E80000000058C3".decode('hex')
]

def get_payload_indexes(s):
    r = []
    for p in GET_PAYLOAD_FUNCTIONS:
        i = s.find(p)
        while i >= 0:
            r.append(i + len(p))
            i = s.find(p, i + 1)
    r.sort()
    return r

for path in sys.argv[1:]:
    with open(path, 'rb') as f:
        file_content = f.read()
    for offset_to_bin in get_payload_indexes(file_content):
        rc4_key, \
        added_code_size, \
        rc4_key_size, \
        filename_size, \
        filename_wide_size, \
        pe_size, \
        launch_type = \
            struct.unpack("16s" + "I" * 6, file_content[offset_to_bin:][:40])
        if launch_type not in (1, 2):
            sys.stderr.write(
                "Possibly invalid header (launch_type = {:d}) at {:s}:{:d}\n".format(
                    launch_type, path, offset_to_bin
                )
            )
        rc4_key = ''.join([ chr(ord(c) ^ 0x37) for c in rc4_key[:rc4_key_size] ])
        i = offset_to_bin + 40
        filename = ARC4.new(rc4_key).decrypt(file_content[i:][:filename_size])[:-1]
        i += filename_size
        filename_wide = ARC4.new(rc4_key).decrypt(file_content[i:][:filename_wide_size])
        filename_wide = filename_wide.decode('utf-16')[:-1]
        i += filename_wide_size
        pe = ARC4.new(rc4_key).decrypt(file_content[i:][:pe_size])
        if pe[:2] == 'MZ':
            payload_sha1 = hashlib.sha1(pe).hexdigest()
            desc = {
                "parent_sha1": hashlib.sha1(file_content).hexdigest(),
                "rc4_key": rc4_key,
                "filename": filename,
                "filename_w": filename_wide,
                "launch_type": launch_type,
                "payload_sha1": payload_sha1,
            }
            if os.path.exists(payload_sha1):
                sys.stderr.write("File {:s} already exists, skipping\n".format(
                    payload_sha1
                ))
            else:
                with file(payload_sha1, "wb") as o:
                    o.write(pe)
            json.dump(desc, sys.stdout)
            sys.stdout.write("\n")
        else:
            sys.stderr.write(
                "Payload not decrypted sucessfully at {:s}:{:d}\n".format(
                    path, offset_to_bin
                )
            )
