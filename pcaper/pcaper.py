#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2018 Alexander Grechin
#
# Licensed under the BSD 3-Clause license.
# See LICENSE file in the project root for full license information.
#

""" Parse pcap file and asseble HTTP requests
"""

import dpkt
import socket
from dpkt.compat import BytesIO
import re
from six import string_types


class HTTPRequest:

    def __init__(self):
        self.info = {}
        self.METHODS = dpkt.http.Request._Request__methods
        self.PROTO = dpkt.http.Request._Request__proto

    def read_pcap(self, params):
        """Read pcap file and assemble http requests"""

        self.info = {
            "total": 0,
            "complete": 0,
            "incorrect": 0,
            "incomplete": 0,
        }
        input_file_handler = open(params['input'], 'rb')
        try:
            pcap = dpkt.pcap.Reader(input_file_handler)
        except ValueError:
            try:
                pcap = dpkt.pcapng.Reader(input_file_handler)
            except ValueError:
                print("UPS: Unexpected pcap file format")
                print("Try to convert file with \"" +
                      "mergecap %s -w out.pcap -F pcap\"\n" % params['input'])
                raise

        streams = dict()
        for timestamp, packet in pcap:
            eth_packet = dpkt.ethernet.Ethernet(packet)
            ip_packet = eth_packet.data
            tcp_packet = ip_packet.data
            tcp_packet.data = tcp_packet.data.decode("utf-8", "replace")

            # remove cache on new or final packets
            if self.tcp_flags(tcp_packet.flags) in ("S", "R", "F"):
                if tcp_packet.sport in streams:
                    self.info["incomplete"] = self.info["incomplete"] + 1
                    del streams[tcp_packet.sport]
            # filter tcp packets
            elif ("filter" not in params
                    or self.filter_packet(
                        params["filter"],
                        eth_packet,
                        ip_packet,
                        tcp_packet
                    )) and tcp_packet.data != '':  # not empty data
                # HTTP request
                if self.starts_with_http_method(tcp_packet.data):
                    self.info["total"] = self.info["total"] + 1
                    streams[tcp_packet.sport] = {
                        'data': tcp_packet.data,
                        'timestamp': timestamp
                    }
                # the next packet
                elif tcp_packet.sport in streams:
                    streams[tcp_packet.sport]['data'] = \
                        streams[tcp_packet.sport]['data'] + tcp_packet.data
                else:
                    continue
                if tcp_packet.sport in streams:
                    http_request = self.parse_request(
                        streams[tcp_packet.sport]['data']
                    )
                    if http_request is None:
                        self.info["incorrect"] = self.info['incorrect'] + 1
                        del streams[tcp_packet.sport]
                        continue
                    http_request['origin'] = \
                        streams[tcp_packet.sport]['data']
                    http_request['timestamp'] = \
                        streams[tcp_packet.sport]['timestamp']
                    if not self.is_complete_request(http_request):
                        continue
                    self.info["complete"] = self.info["complete"] + 1
                    del streams[tcp_packet.sport]
                    http_request['src'] = socket.inet_ntoa(ip_packet.src)
                    http_request['dst'] = socket.inet_ntoa(ip_packet.dst)
                    http_request['sport'] = tcp_packet.sport
                    http_request['dport'] = tcp_packet.dport
                    yield http_request

        self.info["incomplete"] = self.info["incomplete"] + len(streams)
        input_file_handler.close()

    def tcp_flags(self, flags):
        """Check tcp ack flags"""

        ret = ''
        if flags & dpkt.tcp.TH_FIN:
            ret = ret + 'F'
        if flags & dpkt.tcp.TH_SYN:
            ret = ret + 'S'
        if flags & dpkt.tcp.TH_RST:
            ret = ret + 'R'
        if flags & dpkt.tcp.TH_PUSH:
            ret = ret + 'P'
        if flags & dpkt.tcp.TH_ACK:
            ret = ret + 'A'
        if flags & dpkt.tcp.TH_URG:
            ret = ret + 'U'
        if flags & dpkt.tcp.TH_ECE:
            ret = ret + 'E'
        if flags & dpkt.tcp.TH_CWR:
            ret = ret + 'C'
        return ret

    def starts_with_http_method(self, packet):
        """Check the packet starts with HTTP method"""

        for method in self.METHODS:
            if packet.startswith(method):
                return True
        return False

    def filter_packet(self, filter_string, eth, ip=None, tcp=None):
        """Filter packet
        Example: tcp.dport == 80
        """

        def eval_filter(filter_string, eth, ip=None, tcp=None):
            match = re.search(r'(ip.(?:src|dst) *== *)(.+)', filter_string)
            if match:
                return eval(
                    match.group(1) +
                    'b\'' +
                    socket.inet_aton(match.group(2)).decode("utf-8") +
                    '\''
                )
            return eval(filter_string)

        if filter_string is None or filter_string == '':
            return True

        or_split = re.split(r' +or +', filter_string)
        if len(or_split) > 1:
            for elem in or_split:
                if eval_filter(elem, eth, ip, tcp):
                    return True
            return False

        and_split = re.split(r' +and +', filter_string)
        if len(and_split) > 1:
            for elem in or_split:
                if not eval_filter(elem, eth, ip, tcp):
                    return False
            return True

        return eval_filter(filter_string, eth, ip, tcp)

    def is_complete_request(self, http_request):
        """Check that HTTP request is complete"""

        content_length = self.get_content_length(http_request)
        if content_length is not None \
                and len(http_request['body']) == content_length:
            return True
        if http_request['method'] in ['GET', 'PUT'] \
                and http_request['origin'][-4:] == "\r\n\r\n":
            return True
        elif http_request['method'] == 'POST' \
                and http_request['origin'][-2:] == "\r\n" \
                and http_request['origin'][-4:] != "\r\n\r\n":
            return True
        return False

    def get_content_length(self, http_request):
        if 'content-length' in http_request['headers']:
            if (
                isinstance(
                    http_request['headers']['content-length'],
                    string_types
                )
            ):
                return int(http_request['headers']['content-length'])
        return None

    def parse_request(self, data):
        """Parse HTTP headers without body"""

        request = {}
        f = BytesIO(data.encode("utf-8", "replace"))
        line = f.readline().decode("utf-8", "replace")
        parts = line.strip().split()
        if len(parts) < 2:
            # raise dpkt.UnpackError('invalid request: %r' % line)
            return None
        if parts[0] not in self.METHODS:
            # dpkt.UnpackError('invalid http method: %r' % parts[0])
            return None
        if len(parts) == 2:
            # HTTP/0.9 does not specify a version in the request line
            request['version'] = '0.9'
        else:
            if not parts[2].startswith('HTTP/'):
                # raise dpkt.UnpackError('invalid http version: %r' % parts[2])
                return None
            request['version'] = parts[2].split("/")[1]
        request['method'] = parts[0]
        request['uri'] = parts[1]
        request['headers'] = dpkt.http.parse_headers(f)

        if 'content-length' in request['headers']:
            if not isinstance(
                        request['headers']['content-length'],
                        string_types
                    ):
                return None
            try:
                request['body'] = dpkt.http.parse_body(f, request['headers'])
                if 'body' not in request:
                    request['body'] = ''
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                return None
        return request

    def get_stats(self):
        """Get stats captured during parsing of pcap file"""

        return self.info
