#!/usr/bin/env python
#
# Code related to ESET's Miniduke research
# For feedback or questions contact us at: github@eset.com
# https://github.com/eset/malware-research/
#
# This code is provided to the community under the two-clause BSD license as
# follows:
#
# Copyright (c) 2014, ESET
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
# Usage example: python main_dga.py 2014-05-26 4
#
import sys
import hashlib
import datetime
from array import *
import base64
  
def init_params(date_time):
    duke_string = "vSkadnDljYE74fFk"
    to_hash = array("B")
    for ix in xrange(0x40):
        to_hash.append(0)
    for ix in xrange(len(duke_string)):
        to_hash[ix + 8] = ord(duke_string[ix])
    to_hash[0] = (date_time.day / 7)
    to_hash[2] = date_time.month
    to_hash[4] = date_time.year & 0xFF
    to_hash[5] = date_time.year >> 8
    return to_hash
 
 
def hash_data(to_hash):
    m = hashlib.md5()
    m.update(to_hash.tostring())
    hash_val = m.digest()
    first_dword = ord(hash_val[0]) | (ord(hash_val[1]) << 8) | (ord(hash_val[2]) << 16) | (ord(hash_val[3]) << 24)
    last_dword = ord(hash_val[12]) | (ord(hash_val[13]) << 8) | (ord(hash_val[14]) << 16) | (ord(hash_val[15]) << 24)
    new_dword = (first_dword + last_dword) & 0xFFFFFFFF
    to_append = array("B", [new_dword & 0xFF,  (new_dword >> 8) & 0xFF, (new_dword >> 16) & 0xFF, (new_dword >> 24) & 0xFF])
    return hash_val + to_append.tostring()
 
 
def generate_twitter_dga(date_time):
    to_hash = init_params(date_time)
    hash_val = hash_data(to_hash)
    hash_val_encoded = base64.b64encode(hash_val)
    dga_len = ord(hash_val_encoded[0]) | (ord(hash_val_encoded[1]) << 8) | (ord(hash_val_encoded[2]) << 16) | (ord(hash_val_encoded[3]) << 24)
    dga_len = dga_len % 6
    dga_len += 7
    if hash_val_encoded[0] <= 0x39:
        hash_val_encoded[0] = 0x41
    dga_res = ""
     
    for i in xrange(dga_len):
        if hash_val_encoded[i] == '+':
            dga_res += 'a'
        elif hash_val_encoded[i] == '/':
            dga_res += '9'
        else:
            dga_res += hash_val_encoded[i]
 
    return dga_res
 
 
start_date = datetime.datetime.strptime(sys.argv[1], "%Y-%m-%d")
number_of_weeks = long(sys.argv[2])
for ix in xrange(number_of_weeks):
    print generate_twitter_dga(start_date + datetime.timedelta(days=7 * ix))
