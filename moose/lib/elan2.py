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
import re
import socket
from struct import unpack
import sys

def decrypt_cnc_msg(ct):
    """
    Decrypt strings
    ct: bytearray of the ciphertext
    returns bytearray of the plaintext
    """

    # seed
    k = 0xff
    for i in reversed(range(len(ct))):

        # XOR with previous
        k = ct[i] = ct[i] ^ k

    return ct

def parse_cnc1_config(f):
    data = {}

    # The IP that the C&C sees you coming from
    # used to call it magic_bytes
    data['cnccfg_ext_ip'] = socket.inet_ntoa(f.read(4))
    data['cnccfg_nb_thdscan_local'] = unpack('I', f.read(4))[0]
    data['cnccfg_nb_thdscan_ext'] = unpack('I', f.read(4))[0]

    # the 3rd word is a bitfield
    third_field = unpack('I', f.read(4))[0]
    data['cnccfg_flag_scanner_sniffer'] = bool(third_field & 1)
    data['cnccfg_flag_nolocalscan'] = bool(third_field & 2)
    data['cnccfg_flag_noextscan'] = bool(third_field & 4)
    data['cnccfg_flag_test10073'] = bool(third_field & 8)
    data['cnccfg_flag_nattraversal'] = bool(third_field & 16)
    # this one is only stored on the second contact with the C&C
    data['cnccfg_flag_recontactcnc'] = bool(third_field & 32)
    # in new samples this also controls if we report telnet login to C&C 3
    # hijackdns must be ON to report telnet logins
    data['cnccfg_flag_hijackdns'] = bool(third_field & 64)
    # a sniffer is activated only if cnccfg_flag_scanner_sniffer is ON
    # on every non-loopback interfaces
    data['cnccfg_flag_thd_sniffer'] = bool(third_field & 128)
    data['cnccfg_flag_killprocess'] = bool(third_field & 1024)
    data['cnccfg_flag_share_peers'] = bool(third_field & 2048)

    data['cnccfg_proxy_max_clients'] = unpack('I', f.read(4))[0]
    # time to sleep between interactions with C&C 2
    data['cnccfg_relaycnc_sleep'] = unpack('I', f.read(4))[0]
    data['cnccfg_reportcnc_ip'] = socket.inet_ntoa(f.read(4))
    data['cnccfg_relaycnc_ip'] = socket.inet_ntoa(f.read(4))
    data['cnccfg_relaycnc_timeout'] = unpack('I', f.read(4))[0]
    data['cnccfg_hijackdns1_ip'] = unpack('I', f.read(4))[0]
    data['cnccfg_hijackdns2_ip'] = unpack('I', f.read(4))[0]

    return data

def parse_cnc1_cracklist(f, results=False):
    data = {}

    data['userpass_list_len'] = unpack('I', f.read(4))[0]

    # user/pass list 
    pass_list = bytearray(f.read(data['userpass_list_len']))
    if results:
        data['wordlist'] = decrypt_cnc_msg(pass_list)

    return data

def parse_cnc1_whitelist_seg(f):
    """deals with server whitelist allowed to connect to 10073"""

    data = {}

    # size then ip / flag pairs until size * 8
    data['whitelist_len'] = unpack('I', f.read(4))[0]
    whlst = list()
    for pair in range(data['whitelist_len']):
        whlst_entry = {}
        whlst_entry['ip'] = socket.inet_ntoa(f.read(4))
        whlst_flags = unpack('I', f.read(4))[0]
        whlst_entry['can_email'] = bool(whlst_flags & 1)
        whlst.append(whlst_entry)

    data['whitelist'] = whlst
    return data

def parse_cnc1_sniffer_config(f):
    data = {}

    # optional data
    # consumed if cnccfg_flag_thd_sniffer is set
    opt_data = f.read(4)
    if opt_data:
        data['snfcfg_nb_items'] = unpack('I', opt_data)[0]
        for i in range(data['snfcfg_nb_items']):
            snfcfg_item_size = unpack('I', f.read(4))[0]
            snfcfg_item = decrypt_cnc_msg(bytearray(f.read(snfcfg_item_size)))
            #data['snfcfg_{:02d}_len'.format(i)] = snfcfg_item_size
            data['snfcfg_{:02d}_needle'.format(i)] = snfcfg_item.decode('ascii')

    return data

def parse_cnc_request(f):
    data = {}

    # bot version
    # we've seen 0x1C, 0x1D, 0x1F
    data['version'] = unpack('I', f.read(4))[0]
    data['msg_type'] = unpack('I', f.read(4))[0]
    if data['msg_type'] == 0x01:
        data = parse_cnc_request_config(f, data)
        f.read(8)

    elif data['msg_type'] == 0x0E:
        data['msg_type_decoded'] = 'REPORT_TELNET_LOGIN'
        data['ipaddr'] = socket.inet_ntoa(f.read(4))
        f.read(28)

    elif data['msg_type'] == 0x0F:
        data = parse_cnc_request_infect(f, data)
        f.read(20)

    elif data['msg_type'] == 0x14:
        data['msg_type_decoded'] = 'REPORT_SNIFF'
        data['pkt_len'] = unpack('I', f.read(4))[0]
        f.read(28)

    # REPORT_SNIFF additional payload
    if data['msg_type'] == 0x14:
        ct = bytearray(f.read(data['pkt_len']))
        data['sniff_payload'] = decrypt_cnc_msg(ct)

    # REPORT_GOT_SHELL additional payload
    if data['msg_type'] == 0x0f:
        data['cpu_model_len'] = unpack('I', f.read(4))[0]
        data['cpu_model'] = decrypt_cnc_msg(bytearray(f.read(data['cpu_model_len'])))
        data['processor_len'] = unpack('I', f.read(4))[0]
        data['processor'] = decrypt_cnc_msg(bytearray(f.read(data['processor_len'])))

    return data

def parse_cnc_request_config(f, data):

    data['msg_type_decoded'] = 'REQUEST_CONFIG'
    data['loop_count'] = unpack('I', f.read(4))[0]
    data['nb_localscans'] = unpack('I', f.read(4))[0]
    data['nb_extscans'] = unpack('I', f.read(4))[0]
    # number of scans done in per-interface scan threads
    data['nb_ifscans'] = unpack('I', f.read(4))[0]
    data['nb_killed'] = unpack('I', f.read(4))[0]

    # 0x1C is a bitfield
    off_1C = unpack('I', f.read(4))[0]
    data['flag_BRUTEFORCE_LIST'] = bool(off_1C & 1)
    data['flag_WRITE_ACCESS'] = bool(off_1C & 2)
    data['flag_TIME_PROBLEM'] = bool(off_1C & 128)
    #data['flag_'] = bool(off_1C & 8)

    return data

def parse_cnc_request_infect(f, data):

    data['msg_type_decoded'] = 'REPORT_GOT_SHELL'
    data['ipaddr'] = socket.inet_ntoa(f.read(4))
    data['lst_userpass_offset'] = unpack('I', f.read(4))[0]
    # 0x10 is a bitfield
    data['infect_state'] = unpack('I', f.read(4))[0]
    off_10 = data['infect_state']
    data['infect_state_NO_CHMOD'] = bool(off_10 & 1)
    data['infect_state_NO_ECHO'] = bool(off_10 & 2)
    data['infect_state_FOUND_NEAR_SCAN'] = bool(off_10 & 4)
    data['infect_state_PS_BLKLST_HIT'] = bool(off_10 & 0x80)

    return data

def parse_cnc3_response(f):
    data = {}

    idx = 0
    data_len = unpack('I', f.read(4))[0]
    while data_len != 0:
        data['cmd_{!s}'.format(idx)] = decrypt_cnc_msg(bytearray(f.read(data_len))).decode('ascii')

        data_len = unpack('I', f.read(4))[0]
        idx+=1
        
    return data

def parse_rnde_query(s):
    """
    Data from our sinkhole will be full of 127.x.y.z IPs. This is because
    our host configuration makes the malware reply to it. You can ignore these
    hits which are local only
    """
    data = {}

    m = re.search(r'^\/xx\/rnde\.php\?p=(-?\d+)&f=(\d+)&m=(\d)$', s)
    if not m:
        data['error'] = "PARSING ERROR!"
        return data

    # decrypt IP
    packed_ip = (int(m.group(1)) ^ 0x7890ABCD).to_bytes(4, byteorder='little', signed=True)
    data['ip_reported'] = socket.inet_ntoa(packed_ip)

    # byte order (endianness)
    if int(m.group(2)) == 0:
        data['reporter_byteorder'] = 'big'
    else:
        data['reporter_byteorder'] = 'little'

    # thd_scanner config param: was scan for external or close?
    data['flag_ext_scan'] = bool(int(m.group(3)))

    return data
