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
# Olivier Bilodeau <bilodeau@eset.com>
#
# Run tshark with specific filters. Some of the filters will yield the
# hex-encoded payload. Use tshark_to_raw.py to convert these into raw binary
# output.
#
# Some entries require HTTP dissector to be disabled. We use a custom profile
# to do so: -C disable-dissectors.
# Copy wireshark-profile/disable-dissectors/ in your ~/.wireshark/profiles/
# See https://ask.wireshark.org/questions/9544/how-to-disable-dissectors-in-tshark
PATH=/usr/bin:/bin:/usr/local/bin/

TYPE=$1
PCAP=$2

errcho() { echo "$@" 1>&2; }

if [ "z$PCAP" == "z" ] || [ "z$TYPE" == "z" ]; then
	errcho Missing arguments.
	errcho Please read script to understand them
	exit 1
fi

case "$TYPE" in
	cnc1-request)
		# requests sent to current C&C #1
		FILTER="(ip.dst_host == 77.247.177.87 or ip.dst_host == 85.159.237.107 or ip.dst_host == 85.159.237.108) and tcp.dstport == 81 and data"
		FIELDS="-e tcp.stream -e frame.time_relative -e data"
		;;

	cnc1-request-old)
		# requests sent to previous C&C #1
		FILTER="ip.dst_host == 77.247.177.36 and tcp.dstport == 81 and data"
		FIELDS="-e tcp.stream -e frame.time_relative -e data"
		;;

	cnc1-response)
		# replies from C&C #1
		FILTER="ip.src_host == 77.247.177.36 and tcp.srcport == 81 and data"
		FIELDS="-e tcp.stream -e frame.time_relative -e data"
		;;

	cnc1-http)
		# will find GET /xx/rnde.php or elan2 downloads
		FILTER="ip.addr == 77.247.177.36 and tcp.port == 81 and http"
		FIELDS="-e frame.time_relative -e ip.src_host -e ip.dst_host"
		;;

	cnc1-reported)
		# extract GET URI
		FILTER="ip.addr == 77.247.177.36 and tcp.port == 81 and http.request.uri"
		FIELDS="-e frame.time -e http.request.uri"
		;;

	cnc2)
		# C&C 2 related
		FILTER="ip.host == 93.190.140.221 and tcp.port == 80 and data"
		FIELDS="-e tcp.stream -e frame.time -e data"
		OTHER_ARGS="-C disable-dissectors"
		;;

	cnc2-multitunnel)
		FILTER="ip.host == 93.190.140.221 and tcp.port == 80 and data[00] == 0x17 && data[01] == 0x00"
		FIELDS="-e tcp.stream -e frame.time -e data"
		OTHER_ARGS="-C disable-dissectors"
		;;

	cnc3-request)
		# requests from C&C 3
		FILTER="(ip.dst_host == 85.159.237.107 or ip.dst_host ==  85.159.237.108) and tcp.dstport == 81 and data"
		FIELDS="-e tcp.stream -e frame.time_relative -e data"
		;;

	cnc3-response)
		# responses from C&C 3
		FILTER="(ip.src_host == 85.159.237.107 or ip.src_host ==  85.159.237.108) and tcp.srcport == 81 and data"
		FIELDS="-e tcp.stream -e frame.time_relative -e data"
		;;

	telnet-hosts)
		# incoming telnet traffic (means we were able to exchange data)
		FILTER="tcp.srcport == 23 and telnet"
		FIELDS="-e frame.time_relative -e ip.src_host"
		;;

	whitelisted)
		# IPs in whitelist and 10073 activity
		FILTER="(ip.addr == 109.201.148.201 or ip.addr == 103.238.216.28 or ip.addr == 103.238.216.26 or ip.addr == 109.236.86.18 or ip.addr == 103.238.216.23 or ip.addr == 27.124.41.52 or ip.addr == 103.238.216.22 or ip.addr == 27.124.41.11 or ip.addr == 27.124.41.33 or ip.addr == 27.124.41.33 or ip.addr == 93.190.143.60 or ip.addr == 217.23.2.252 or ip.addr == 103.238.216.216 or ip.addr == 93.190.139.123 or ip.addr == 103.238.216.25 or ip.addr == 109.236.89.208 or ip.addr == 42.119.173.138 or ip.addr == 27.124.41.31 or ip.addr == 93.190.139.147 or ip.addr == 85.159.237.111 or ip.addr == 77.247.177.31 or ip.addr == 217.23.2.47 or ip.addr == 217.23.2.48 or ip.addr == 103.238.216.24 or ip.addr == 217.23.2.249 or ip.addr == 85.159.237.107 or ip.addr == 27.124.41.52 or ip.addr == 127.0.0.1 or ip.addr == 103.238.216.21 or ip.addr == 217.23.7.211 or ip.addr == 27.124.41.31 or ip.addr == 109.201.148.136 or ip.addr == 77.247.178.177 or ip.addr == 192.168.1.3 or ip.addr == 217.23.2.30 or ip.addr == 79.176.26.142 or ip.addr == 217.23.2.251 or ip.addr == 109.201.148.241 or ip.addr == 85.159.237.111 or ip.addr == 192.126.184.234 or ip.addr == 217.23.2.49 or ip.addr == 207.244.67.193 or ip.addr == 103.238.216.30 or ip.addr == 103.238.216.31 or ip.addr == 93.190.142.113 or ip.addr == 217.23.7.133 or ip.addr == 82.146.63.15 or ip.addr == 217.23.12.124 or ip.addr == 103.238.216.217 or ip.addr == 217.23.2.52 or ip.addr == 217.23.2.79 or ip.addr == 103.238.216.29 or ip.addr == 217.23.2.253 or ip.addr == 85.159.237.108 or ip.addr == 77.247.177.36 or ip.addr == 103.238.216.218 or ip.addr == 93.190.140.221) and tcp.port == 10073"
		FIELDS="-e frame.time_relative -e ip.src_host -e ip.dst_host"
		;;

	whitelisted-anyproto)
		# IPs in whitelist with any proto and cnc1, 2 and 3 removed
		FILTER="ip.addr == 109.201.148.201 or ip.addr == 103.238.216.28 or ip.addr == 103.238.216.26 or ip.addr == 109.236.86.18 or ip.addr == 103.238.216.23 or ip.addr == 27.124.41.52 or ip.addr == 103.238.216.22 or ip.addr == 27.124.41.11 or ip.addr == 27.124.41.33 or ip.addr == 27.124.41.33 or ip.addr == 93.190.143.60 or ip.addr == 217.23.2.252 or ip.addr == 103.238.216.216 or ip.addr == 93.190.139.123 or ip.addr == 103.238.216.25 or ip.addr == 109.236.89.208 or ip.addr == 42.119.173.138 or ip.addr == 27.124.41.31 or ip.addr == 93.190.139.147 or ip.addr == 85.159.237.111 or ip.addr == 77.247.177.31 or ip.addr == 217.23.2.47 or ip.addr == 217.23.2.48 or ip.addr == 103.238.216.24 or ip.addr == 217.23.2.249 or ip.addr == 27.124.41.52 or ip.addr == 127.0.0.1 or ip.addr == 103.238.216.21 or ip.addr == 217.23.7.211 or ip.addr == 27.124.41.31 or ip.addr == 109.201.148.136 or ip.addr == 77.247.178.177 or ip.addr == 192.168.1.3 or ip.addr == 217.23.2.30 or ip.addr == 79.176.26.142 or ip.addr == 217.23.2.251 or ip.addr == 109.201.148.241 or ip.addr == 85.159.237.111 or ip.addr == 192.126.184.234 or ip.addr == 217.23.2.49 or ip.addr == 207.244.67.193 or ip.addr == 103.238.216.30 or ip.addr == 103.238.216.31 or ip.addr == 93.190.142.113 or ip.addr == 217.23.7.133 or ip.addr == 82.146.63.15 or ip.addr == 217.23.12.124 or ip.addr == 103.238.216.217 or ip.addr == 217.23.2.52 or ip.addr == 217.23.2.79 or ip.addr == 103.238.216.29 or ip.addr == 217.23.2.253 or ip.addr == 103.238.216.218"
		FIELDS="-e frame.time_relative -e ip.src_host -e ip.dst_host"
		;;

	else)
		# look for anything unknown
		FILTER="!(ip.addr == 77.247.177.36 and tcp.port == 81) and !(ip.addr == 93.190.140.221 and tcp.port == 80) and !((ip.host == 85.159.237.107 or ip.host == 85.159.237.108) and tcp.port == 81)"
		FIELDS="-e frame.time_relative -e ip.src_host -e ip.dst_host"
		;;

	newcnc)
		FILTER="ip.addr == 77.247.177.87"
		FIELDS="-e frame.time_relative -e ip.src_host -e ip.dst_host"
		;;

	infected-peers)
		# warning generates false positives
		# 10073 might be opened, doesn't mean telnet is exposed and brute-forceable
		#FILTER="tcp.flags.ack == 1 and tcp.flags.syn ==1 and tcp.dstport == 10073"
		# TODO: replace with your own hardcoded IP
		IP=127.0.0.1
		FILTER="tcp.flags.ack == 1 and tcp.flags.syn ==1 and tcp.port == 10073 and ip.dst_host == $IP"
		FIELDS="-e frame.time_relative -e ip.src_host"
		;;

	# use of the malware's HTTP Proxy
	http-proxy)
		FILTER="tcp.dstport == 10073 and tcp.seq == 1 and ( data[00] == \"I\" or data[00] == \"i\" or data[00] == \"p\" or data[00] == \"P\" or data[00] == \"g\" or data[00] == \"G\" or data[00] == \"c\" or data[00] == \"C\" )"
		FIELDS="-e tcp.stream -e frame.time -e ip.src_host -e ip.dst_host"
		OTHER_ARGS="-C disable-dissectors"
		;;

	*)
		errcho "This type of data hasn't been defined"
		errcho Please read script to understand arguments
		exit 2
		;;
esac

tshark -2 -R "$FILTER" -T fields $FIELDS -r $PCAP $OTHER_ARGS
