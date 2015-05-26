#!/bin/bash
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
#
# Prints timestamp, destination IP:port for each socks4 request received in
# a given pcap
#
# Marc-Etienne M.Leveille <leveille@eset.com>
# Olivier Bilodeau <bilodeau@eset.com>

if [ "$1" == "-h" ]; then
	echo "Usage:"
	echo "$0 <file.pcap>"
	echo "mergecap -w- <file.pcap> [<file1.pcap> ...] | $0"
	exit 1
fi

# input can be from file given on the CLI or STDIN
[ $# -ge 1 -a -f "$1" ] && INPUT="$1" || INPUT="-"

tshark -r "$INPUT" -T fields -e data -e frame.time -Y "data[00] == 0x04 && data[01] == 0x01" | while read line; do
	python -c 'import socket,struct; s,t ="'"$line"'".split("\t"); s=s.decode("hex"); print("%s\t%s:%d" % (t, socket.inet_ntoa(s[4:8]), struct.unpack("!H", s[2:4])[0]))'
done
