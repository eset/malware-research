# This script extracts the shellcode of the fake and malicious "rastls.dll"
# used in OceanLotus latest campaign using the side-loading technique against 
# legitimate "rastls.exe" application from Symantec
# Details about OceanLotus can be found at 
# https://www.welivesecurity.com/wp-content/uploads/2018/03/ESET_OceanLotus.pdf
#
# For feedback or questions contact us at: github@eset.com
# https://github.com/eset/malware-research/
# Romain Dumont <romain.dumont@eset.com>
#
# This code is provided to the community under the two-clause BSD license as
# follows:
#
# Copyright (C) 2018 ESET
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
#encoding: utf-8

import sys
import pylzma
from Crypto.Cipher import AES
from struct import unpack

if len(sys.argv) != 4:
    print "Usage: rastls_dll_shellcode_dropper rastls.dll encrypted_shellcode shellcode.bin"
    exit(-1)

with open(sys.argv[1], "rb") as f:
    data = f.read()
marker = "!!!!@@@@".encode("utf-16le")
i = data.find(marker) + len(marker)
while data[i] == "\x00":
    i += 1

key = data[i:i+0x20]
iv = data[i+0x20:i+0x30]
a = AES.new(key,AES.MODE_CBC, iv)
with open(sys.argv[2],"rb") as f:
    compressedShellcode = a.decrypt(f.read())
size = unpack("<I", compressedShellcode[4:8])[0]
shellcode = pylzma.decompress(compressedShellcode[8:], maxlength=size)
with open(sys.argv[3],"wb") as f:
    f.write(shellcode)
