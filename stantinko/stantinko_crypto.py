#!/usr/bin/env python
#
# Code related to ESET's Stantinko research.
# Library used to decrypt Stantinko network communication.
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

import base64
import struct
import zlib

from Crypto.Cipher import ARC4
from Crypto.Hash import MD5


class BaseStantinkoDecryptor(object):
    def __init__(self):
        self.time = None
        self.name = None
        self.payload = None
        self.errors = []

    def _decrypt(self, data, key):
        key_ = MD5.new(key).hexdigest()
        cipher = ARC4.new(key_)
        return cipher.decrypt(data)


class PDSIResponseDecryptor(BaseStantinkoDecryptor):
    def __init__(self):
        super(self.__class__, self).__init__()

    def parse_response(self, response):
        try:
            data = base64.b64decode(response)
        except TypeError as e:
            self.errors.append(e)
            return

        param1 = b"g="
        sep = b"&"
        marker = b"***"

        i1 = data.find(param1, 0)
        i2 = data.find(sep, i1)
        if i2 == -1:
            self.payload = ""
            return

        time = data[i1+len(param1):i2]

        beg_data = i2 + len(sep)
        checksum = struct.unpack("<I", data[beg_data+4:beg_data+8])[0]
        length = struct.unpack("<I", data[beg_data:beg_data+4])[0]

        i4 = data.find(marker, beg_data)
        cipher = data[i4+len(marker):]

        headers_len = 8
        self.name = data[beg_data+headers_len:i4]

        data = self._decrypt(cipher, time)

        if not (zlib.crc32(data) & 0xffffffff) == checksum:
            self.errors.append("Invalid checksum")
        if not len(data) == length:
            self.errors.append("Invalid length")

        try:
            self.payload = zlib.decompress(data)
        except zlib.error as e:
            self.errors.append(e)


class PDSClientDecryptor(BaseStantinkoDecryptor):
    def __init__(self):
        super(self.__class__, self).__init__()

    def parse_response(self, response):
        param1 = b"g="
        sep = b"&"
        param2 = b"a="

        i1 = response.find(param1)
        i2 = response.find(sep, i1 + len(param1))
        if i1 == -1:
            self.errors.append("Invalid format: Missing param {}".format(param1))
            return

        time = response[i1+len(param1):i2]

        i3 = response.find(param2, i2+len(sep))

        if i3 == -1:
            self.errors.append("Invalid format: Missing param {}".format(param2))
            return

        try:
            data = base64.b64decode(response[i3+len(param2):])
        except TypeError as e:
            self.errors.append(e)
            return

        self.payload = self._decrypt(data, time)


class PDSResponseDecryptor(BaseStantinkoDecryptor):
    def __init__(self):
        super(self.__class__, self).__init__()
        self.param = None

    def parse_response(self, response):
        try:
            data = base64.b64decode(response)
        except TypeError as e:
            self.errors.append(e)
            return

        param1 = b"g="
        sep = b"&"
        param2 = b"p="
        param3 = b"a="
        marker = b"***"

        i1 = data.find(param1, 0)
        i2 = data.find(sep, i1)
        if i2 == -1:
            self.payload = ""
            return

        time = data[i1+len(param1):i2]

        i3 = data.find(param2, i2+len(sep), data.find(marker))
        self.param = "p"

        if i3 == -1:
            i3 = data.find(param3, i2+len(sep), data.find(marker))
            self.param = "a"
            if i3 == -1:
                self.payload = ""
                return

        checksum = struct.unpack("<I", data[i3+6:i3+10])[0]
        length = struct.unpack("<I", data[i3+2:i3+6])[0]

        i4 = data.find(marker, i3+len(self.param)+1)
        cipher = data[i4+len(marker):]

        headers_len = 8
        self.name = data[i3+len(self.param)+1+headers_len:i4]

        data = self._decrypt(cipher, time)

        if not (zlib.crc32(data) & 0xffffffff) == checksum:
            self.errors.append("Invalid checksum")
        if not len(data) == length:
            self.errors.append("Invalid length")

        try:
            self.payload = zlib.decompress(data)
        except zlib.error as e:
            self.errors.append(e)


class BEDSClientDecryptor(BaseStantinkoDecryptor):
    def __init__(self):
        super(self.__class__, self).__init__()

    def parse_response(self, response):
        param1 = b"date="
        sep = b"&"
        param2 = b"data="

        i1 = response.find(param1)
        i2 = response.find(sep, i1 + len(param1))
        if i1 == -1:
            self.errors.append("Invalid format : Missing param {}".format(param1))
            return

        time = response[i1+len(param1):i2]

        i3 = response.find(param2, i2+len(sep))

        if i3 == -1:
            self.errors.append("Invalid format: Missing param {}".format(param2))
            return

        try:
            data = base64.b64decode(response[i3+len(param2):])
        except TypeError as e:
            self.errors.append(e)
            return

        self.payload = self._decrypt(data, time)


class BEDSResponseDecryptor(BaseStantinkoDecryptor):
    def __init__(self):
        super(self.__class__, self).__init__()

    def parse_response(self, response):
        try:
            data = base64.b64decode(response)
        except TypeError as e:
            self.errors.append(e)
            return

        param1 = b"date="
        param2 = b"data="
        sep = b"&"

        i1 = data.find(param1, 0)
        if i1 == -1:
            self.errors.append("Response doesn't contain '{}' parameter".format(param1))

        i2 = data.find(sep, i1)
        t = data[i1+len(param1):i2]

        i3 = data.find(param2, i2+len(sep))
        if i2 == -1 or i3 == -1:
            self.errors.append("Response doesn't contain '{}' parameter".format(param2))

        cipher = data[i3+len(param2):]

        self.payload = self._decrypt(cipher, t)

        # Heuristic: If the payload is more than 4KB, it might be a PE
        if len(self.payload) > 4096:
            marker1 = b"\xE5\x31\x99\xD0\xA7\x7B\xA6\x23"
            i4 = self.payload.find(marker1)
            i5 = self.payload.find(b"\x7B", i4 + len(marker1))
            if i4 == -1 or i5 == -1:
                self.errors.append("Response has an invalid format : marker(s) missing")
                return
            try:
                self.payload = zlib.decompress(self.payload[i5+1:])
                self.name = "binary"
            except zlib.error as e:
                self.errors.append(e)
