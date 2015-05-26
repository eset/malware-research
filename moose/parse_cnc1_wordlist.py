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
from pprint import pprint
import socket
from struct import unpack
import sys

from lib.elan2 import *

def main():
    data = {}

    with open(sys.argv[1], 'rb') as f:

        data.update(parse_cnc1_config(f))
        # fetch wordlist
        data.update(parse_cnc1_cracklist(f, results=True))

    for line in data['wordlist'].decode('ascii').split('\r\n'):
        if line.find(" ") != -1:
            u, p = line.split(' ', 1)
            print("{}:{}".format(u,p))
        else:
            print(line)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Run with: {} <file>".format(sys.argv[0]))
        exit(1)

    main()
