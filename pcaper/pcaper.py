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
from collections import OrderedDict


class HTTPRequest:
    """HTTP requests iterator"""

    def __init__(self):
        """Constructor"""

        self.info = {}
        self.METHODS = dpkt.http.Request._Request__methods
        self.PROTO = dpkt.http.Request._Request__proto

    def read_pcap(self, params):
        """Read pcap and return iterator for assembled HTTP requests

        Args:
            params (dict): input parameters
                "input" : input pcap filename
                "filter": TCP/IP packet filter
                "http_filter": HTTP packet filter
        """

        self.info = OrderedDict()
        self.info["total"] = 0
        self.info["complete"] = 0
        self.info["incorrect"] = 0
        self.info["incomplete"] = 0

        if 'input' not in params or not params['input']:
            raise ValueError('input filename is not specified or empty')
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
        if "filter" in params:
            params["filter"] = self.prepare_filter(params["filter"])
        else:
            params["filter"] = None
        if "http_filter" not in params:
            params["http_filter"] = None

        for timestamp, packet in pcap:
            eth_packet = dpkt.ethernet.Ethernet(packet)
            ip_packet = eth_packet.data
            if not hasattr(ip_packet, 'data'):
                continue
            tcp_packet = ip_packet.data
            if not hasattr(tcp_packet, 'data'):
                continue
            tcp_packet.data = tcp_packet.data.decode("utf-8", "replace")

            # remove cache on new or final packets
            if self.tcp_flags(tcp_packet.flags) in ("S", "R", "F"):
                if tcp_packet.sport in streams:
                    self.info["incomplete"] = self.info["incomplete"] + 1
                    del streams[tcp_packet.sport]
                continue
            # filter tcp packets
            # not empty
            if tcp_packet.data == '':
                continue
            # check filter
            if (params["filter"]
                and not self.filter_packet(
                    params["filter"],
                    eth_packet,
                    ip_packet,
                    tcp_packet
                    )):
                continue
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
                http_request_packet = self.build_http_request_packet(
                    http_request
                )
                if not self.filter_http_packet(
                    params['http_filter'],
                    http_request_packet
                ):
                    continue
                yield http_request_packet

        self.info["incomplete"] = self.info["incomplete"] + len(streams)
        input_file_handler.close()

    def build_http_request_packet(self, request_dict):
        """Convert HTTP request as dict to dpkt.http.Request object

        Args:
            request_dict (dict): HTTP request fields

        Returns:
            dpkt.http.Request: returns dpkt.http.Request object
        """

        request = dpkt.http.Request()
        request.version = request_dict["version"]
        request.uri = request_dict["uri"]
        request.method = request_dict["method"]
        request.headers = request_dict["headers"]
        request.body = request_dict["body"] if 'body' in request_dict else u''
        request.timestamp = request_dict['timestamp']
        request.src = request_dict['src']
        request.sport = request_dict['sport']
        request.dst = request_dict['dst']
        request.dport = request_dict['dport']
        request.origin = request_dict['origin']
        return request

    def tcp_flags(self, flags):
        """Identify TCP ack flags

        Args:
            flags (dpkt.tcp.flags): TCP flags

        Returns:
            str: returns identifiers of TCP flags
        """

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

    def starts_with_http_method(self, data):
        """Check the packet starts with HTTP method

        Args:
            data (str): TCP packet data

        Returns:
            bool: returns True if TCP packet data
                  starts with HTTP request method
        """

        for method in self.METHODS:
            if data.startswith(method):
                return True
        return False

    def prepare_filter(self, filter_string):
        """Get filter string in proper format

        Args:
            filter_string (str): packet filter expression
                                 Example: "tcp.dport == 80"

        Returns:
            str: corresponding filter expression
        """

        def inet_filter(element):
            match = re.search(
                r'(ip.(?:src|dst).*?)(["\']?[\d\.]+["\']?)',
                element
            )
            if match:
                return "%ssocket.inet_aton('%s')" % \
                    (match.group(1), match.group(2))
            return element

        if filter_string:
            return re.sub(
                r'(ip.(?:src|dst).*?)(["\']?[\d\.]+["\']?)',
                lambda m: inet_filter(m.group()),
                filter_string
            )
        return filter_string

    def filter_packet(self, filter_string, eth, ip=None, tcp=None):
        """Filter Ethernet, IP and TCP packets

        Args:
            filter_string (str): packet filter expression
                                 Example: "tcp.dport == 80"
            eth (dpkt.Ethernet): Ethernet packet
            ip (dpkt.IP):        IP packet
            tcp (dpkt.TCP):      TCP packet

        Returns:
            bool: returns True if all provided packets
                  are corresponding filter expression
        """

        if filter_string is not None:
            return eval(filter_string)
        return True

    def filter_http_packet(self, filter_string, http):
        """Filter HTTP packet
        Args:
            filter_string (string): Packet filter
            http (dpkt.http): dpkt HTTP packet

        Returns:
            bool: returns True if HTTP packet
                  is corresponding filter expression
        """

        if filter_string is not None:
            return eval(filter_string)
        return True

    def is_complete_request(self, http_request):
        """Check that HTTP request is complete

        Args:
            http_request (str): HTTP request

        Returns:
            bool: returns True if HTTP request is complete
        """

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
        """Get Content-Length header value

        Args:
            http_request (str): HTTP request

        Returns:
            str: returns Content-Length value
        """

        if 'content-length' in http_request['headers']:
            if (
                # ignore value if multiple Content-Length headers
                isinstance(
                    http_request['headers']['content-length'],
                    string_types
                )
            ):
                return int(http_request['headers']['content-length'])
        return None

    def parse_request(self, data):
        """Parse HTTP request
            "version": protocol version
            "method":  request method
            "uri":     URI
            "headers": headers
            "body":    body

        Args:
            data (str): assembled data of TCP packets

        Returns:
            dict: HTTP request structure
        """

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

        # ignore value if multiple Content-Length headers
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
        """Get stats captured during parsing of pcap file,
           requests should be iterated via "read_pcap" method

            "total":      total requests count
            "complete":   complete requests count
            "incorrect":  count of requests which can't be parsed properly
            "incomplete": count of incomplete requests

        Returns:
            dict: HTTP requests statistics
        """

        return self.info
