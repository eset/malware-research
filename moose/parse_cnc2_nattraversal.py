#!/usr/bin/env python3
#
# Code related to ESET's Linux/Moose research
# For feedback or questions contact us at: github@eset.com
# https://github.com/eset/malware-research/
# Olivier Bilodeau <bilodeau@eset.com>
#
# This code is provided to the community under the two-clause BSD license as
# follows:
#
# Copyright (C) 2015 ESET
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
#
# Pass first 16 hex given by relay C&C to this script and it will output
# request type and tunnel destination (if in tunnel mode)
import fileinput
from socket import inet_ntoa
from struct import unpack

for line in fileinput.input():
    line = line[:-1]

    line = bytearray.fromhex(line)
    #cmd = line[0:2]
    cmd = unpack("!H", line[0:2])[0]
    port = unpack("!H", line[2:4])[0]
    ip = inet_ntoa(bytes(line[4:8]))

    if cmd == 0x0016:
        cmd = "SLEEP"
    elif cmd == 0x0017:
        cmd = "MULTI"
    elif cmd == 0x0000:
        cmd = "TUNNEL"
    else:
        cmd = "TUNNEL_NONSTANDARD"


    print("{}\t{}\t{}".format(cmd, ip, port))
