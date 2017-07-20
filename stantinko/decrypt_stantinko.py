#!/usr/bin/env python
#
# Code related to ESET's Stantinko research.
# This script can decrypt network communication for all Stantinko's components.
# These components are the Plugin Downloader Service Installer, the Plugin Downloader Service (PDS)
# and the Browser Extension Downloader Service (BEDS).
# It decrypt reports sent to the server as well as the server response.
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
import sys

from stantinko_crypto import *


def main(decryptor, filename_in, filename_out):
    with open(filename_in, "rb") as f:
        data = f.read()

    decryptor.parse_response(data)

    if len(decryptor.errors) != 0:
        for err in decryptor.errors:
            print(err, file=sys.stderr)
        sys.exit(-1)

    if filename_out is not None:
        with open(filename_out, "wb") as f:
            f.write(decryptor.payload)
    else:
        print(decryptor.payload)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="This tools decrypts Stantinko communication protocol")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-q", "--pdsquery", help="Decrypt the Plugin Downloader Service (PDS) and PDS "
                                                 "Installer queries",
                        action="store_true", required=False)
    group.add_argument("-r", "--pdsresponse", help="Decrypt the Plugin Downloader Service (PDS) server response",
                        action="store_true", required=False)
    group.add_argument("-b", "--bedsquery", help="Decrypt the Plugin Downloader Service (BEDS) query",
                        action="store_true", required=False)
    group.add_argument("-p", "--pdsiresponse", help="Decrypt the Plugin Downloader Service Installer server responses",
                        action="store_true", required=False)
    group.add_argument("-s", "--bedsresponse", help="Decrypt the Plugin Downloader Service (BEDS) server response",
                        action="store_true", required=False)
    parser.add_argument("-o", "--output", help="The file where to write the decrypted data",
                        metavar="filename", required=False)
    parser.add_argument("-i", "--input", help="The file containing the encrypted data",
                        metavar="filename", required=True)
    args = parser.parse_args()

    decryptor = None
    if args.pdsquery:
        decryptor = PDSClientDecryptor()
    elif args.pdsresponse:
        decryptor = PDSResponseDecryptor()
    elif args.bedsquery:
        decryptor = BEDSClientDecryptor()
    elif args.bedsresponse:
        decryptor = BEDSResponseDecryptor()
    elif args.pdsiresponse:
        decryptor = PDSIResponseDecryptor()

    main(decryptor, args.input, args.output)
