#!/usr/bin/env python3
#
# Code related to ESET's Linux/Moose research
# For feedback or questions contact us at: github@eset.com
# https://github.com/eset/malware-research/
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
# Olivier Bilodeau <bilodeau@eset.com>
#
# Processes output of pcap-extract-traffic.sh and dumps raw binary contained
# in the traffic for further processing.
import fileinput

class TcpParser(object):
    """Parse tshark output and reassemble TCP data of same stream ids"""
    def __init__(self):
        # initialized to false because stream_id of 0 is valid in wireshark 
        self.stream_id = False
        self.data = bytearray()
        self.ts = 0

    def parse_line(self, line):
        stream_id, timestamp, data = line.split("\t")
        data = data[:-1]

        # first run: initialize
        if self.stream_id == False:
            self.stream_id = stream_id
            self.ts = timestamp
            self.data = bytearray.fromhex(data)

        # stream finished: return previous data and start storing new data
        elif stream_id != self.stream_id:
            tcpData = TcpStreamData(self.ts, self.stream_id, self.data)
            self.stream_id = stream_id
            self.ts = timestamp
            self.data = bytearray.fromhex(data)
            return tcpData

        # still in stream append the data
        else:
            self.data.extend(bytearray.fromhex(data))

        return False

    def finalize(self):
        """kind of a hack to get last stream"""
        tcpData = TcpStreamData(self.ts, self.stream_id, self.data)
        self.__init__()
        return tcpData

class TcpStreamData(object):
    """Simple data container for TCP reassembled data"""
    def __init__(self, ts, stream_id, data):
        self.timestamp = ts
        self._id = stream_id
        self.data = data

t = TcpParser()
for line in fileinput.input():
    tcp_stream = t.parse_line(line)
    if tcp_stream != False:
        fn = 'tcpstream-{:09d}.raw'.format(int(tcp_stream._id))
        with open(fn, 'wb') as f:
            f.write(tcp_stream.data)

# last stream
tcp_stream = t.finalize()
fn = 'tcpstream-{:09d}.raw'.format(int(tcp_stream._id))
with open(fn, 'wb') as f:
    f.write(tcp_stream.data)
