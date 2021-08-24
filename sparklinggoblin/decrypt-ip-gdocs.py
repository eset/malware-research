#!/usr/bin/env python3
#
# For feedback or questions contact us at: github@eset.com
# https://github.com/eset/malware-research/
#
# Author: Thibaut Passilly <thibaut.passilly@eset.com>
#
# This code is provided to the community under the two-clause BSD license as
# follows:
#
# Copyright (C) 2021 ESET
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
try:
    from Crypto.Cipher import ChaCha20
except ImportError:
    sys.stderr.write("{} requires pycryptodome (`pip install pycryptodome`)\n".format(sys.argv[0]))
    exit(1)

try:
    with open(sys.argv[1], "r") as r:
        content = r.read()
except:
    sys.stderr.write("Usage : python3 decrypt-ip-gdocs.py input.txt\n")
    exit(1)

LEFT_DELIMITER = "PublicKey:AE6849916EB80C28FE99FC0F3EFF"
RIGHT_DELIMITER = "CC1F99653E93305D"
KEY = b"o71UwSfKrH0NkRhjOmXqFGMAWDplz4s\x00"

ld_index = content.index(LEFT_DELIMITER)
if ld_index >= 0:
    ld_index_end = ld_index + len(LEFT_DELIMITER)
else:
    sys.stderr.write("Left delimiter {!r} not found.\n".format(LEFT_DELIMITER))
    exit(1)

rd_index = content.index(RIGHT_DELIMITER)
if rd_index >= 0:
    rd_index_end = rd_index + len(RIGHT_DELIMITER)
else:
    sys.stderr.write("Right delimiter {!r} not found.\n".format(RIGHT_DELIMITER))
    exit(1)

payload_size = int(content[ld_index_end:ld_index_end + 4], base=16)
sys.stdout.write("Payload size : {}\n".format(payload_size))
payload = content[ld_index_end + 4:rd_index]

if payload_size != len(payload):
    sys.stderr.write("WARNING : payload size is different than expected.\n")

encrypted_ip = bytes.fromhex(payload[0x68:])
nonce = bytes.fromhex(payload[0x48:][:24])

c = ChaCha20.new(key=KEY, nonce=nonce)
# We seek in the keystream by 11 times the block size to set the counter to 11
c.seek(11*64)
result = c.decrypt(encrypted_ip)

sys.stdout.write("Full decrypted buffer: {!r}\n".format(result))

c2_index = result.rfind(b"\x00\x00")
if c2_index >= 0:
    sys.stdout.write("C&C server: {}\n".format(result[c2_index+2:].decode('utf-16-le')))
