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

from __future__ import unicode_literals
import dpkt
from dpkt.udp import UDP
import socket
from dpkt.compat import BytesIO
import re
from six import string_types
from collections import OrderedDict
from .HTTPRequest import HTTPRequest
import json
from datetime import datetime
from dateutil import parser as date_parser
import sys


class HTTPParser:
    """Parse HTTP request"""

    def __init__(self):
        """Constructor"""

        self.METHODS = dpkt.http.Request._Request__methods
        self.PROTO = dpkt.http.Request._Request__proto

    def starts_with_http_method(self, http_request):
        """Check the packet starts with HTTP method

        Args:
            data (str): HTTP request

        Returns:
            bool: returns True if TCP packet data
                  starts with HTTP request method
        """

        for method in self.METHODS:
            if http_request.startswith(method + " "):
                return True
        return False

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

    def parse_body(self, file, headers, fix_incomplete=False):
        """Return HTTP body parsed from a file object, given HTTP header dict

        Args:
            file: BytesIO object
            headers: HTTP request headers as dict

        Returns:
            str: body string"""

        if headers.get('transfer-encoding', '').lower() == 'chunked':
            buffer_list = []
            found_end = False
            while True:
                try:
                    size = file.readline().split(None, 1)[0]
                except IndexError:
                    raise dpkt.UnpackError('missing chunk size')
                n = int(size, 16)
                if n == 0:
                    found_end = True
                buffer = file.read(n)
                if file.readline().strip():
                    break
                if n and len(buffer) == n:
                    buffer_list.append(buffer)
                else:
                    break
            if not found_end:
                raise dpkt.NeedData('premature end of chunked body')
            body = b''.join(buffer_list)
        elif 'content-length' in headers:
            n = int(headers['content-length'])
            body = file.read(n)
            if fix_incomplete:
                headers['content-length'] = len(body)
            elif len(body) != n:
                raise dpkt.NeedData(
                    'short body (missing %d bytes)' % (n - len(body)))
        elif 'content-type' in headers:
            body = file.read()
        else:
            # XXX - need to handle HTTP/0.9
            body = b''
        return body

    def parse_request(self, data, fix_incomplete=False):
        """Parse HTTP request to dict structure:
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
        if sys.version_info[0] == 2 and isinstance(data, str):
            # python2 unicode support
            data = unicode(data, 'utf-8')  # noqa: F821
            # to void undefined name 'unicode' for python3
        file = BytesIO(data.encode("utf-8", "replace"))
        line = file.readline().decode("utf-8", "replace")
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
            request['version'] = parts[2].split('/')[1]
        request['method'] = parts[0]
        request['uri'] = parts[1]
        request['origin_headers'] = self.parse_headers(file)
        request['headers'] = self.headers_to_lower(request['origin_headers'])

        # ignore value if multiple Content-Length headers
        if not fix_incomplete and 'content-length' in request['headers']:
            if not isinstance(
                        request['headers']['content-length'],
                        string_types
                    ):
                return None
        try:
            request['body'] = ''
            request['body'] = self.parse_body(
                file, request['headers'],
                fix_incomplete).decode('ascii', 'ignore')
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
            return None
        return request

    def parse_headers(self, stream):
        """Return dict of HTTP headers parsed from a stream
        Args:
            stream (BytesIO): stream

        Returns:
            dict: HTTP request headers
        """

        headers = OrderedDict()
        while 1:
            line = stream.readline().strip().decode("ascii", "ignore")
            if not line:
                break
            pair = line.split(':', 1)
            if len(pair[0].split()) != 1:
                return headers
            key = pair[0]
            value = len(pair) != 1 and pair[1].lstrip() or ''
            if key in headers:
                if not type(headers[key]) is list:
                    headers[key] = [headers[key]]
                headers[key].append(value)
            else:
                headers[key] = value
        return headers

    def headers_to_lower(self, headers):
        """Return dict of HTTP headers with keys in lower case
        Args:
            headers (dict): HTTP headers dictionary

        Returns:
            dict: HTTP request headers with keys in lower case
        """

        lower_headers = OrderedDict()
        for key, value in headers.items():
            lower_headers[key.lower()] = value
        return lower_headers

    def build_origin(self, http_request):
        """Build origin HTTP request from http_request dictionary

        Args:
            http_request (dict): HTTP request dictionary

        Returns:
            str: HTTP request string
        """

        headers = ''
        body = ''
        base_line = ''
        if 'method' in http_request and 'uri' in http_request and \
                'version' in http_request:
            base_line = '%s %s HTTP/%s' % (
                http_request['method'],
                http_request['uri'],
                http_request['version'],
            )
        if 'origin_headers' in http_request:
            headers = ''.join(
                [
                    '%s: %s\r\n' % (key, value)
                    for key, value in
                    http_request['origin_headers'].items()
                ]
            )
        if 'body' in http_request:
            body = http_request['body']
        return '%s\r\n%s\r\n%s' % (
            base_line, headers, str(body))  # body.decode("utf8", "ignore")


class TextParser:
    """HTTP requests iterator for text file"""

    def __init__(self):
        """Constructor"""

        self.info = OrderedDict()
        self.info['total'] = 0
        self.info['complete'] = 0
        self.info['incorrect'] = 0
        self.info['incomplete'] = 0
        self.delimiter = "%--%"
        self.parser = HTTPParser()

    def read_records(self, filename, delimiter, block_size=4096):
        """Read text file record by record separated with specified delimiter

        Args:
            filename: text filename
            delimiter: specified delimiter for records

        Returns:
            str: iterator for string records
        """

        buffer = ""
        with open(filename, 'r') as f:
            while True:
                chunk = f.read(block_size)
                while True:
                    pos = chunk.find(delimiter)
                    if pos >= 0:
                        pos_delimiter_length = pos + len(delimiter)
                        start_index = pos
                        end_index = pos_delimiter_length
                        if chunk[pos-2:pos] == "\r\n":
                            start_index = pos - 2
                        elif chunk[pos-1:pos] == "\n":
                            start_index = pos - 1
                        if chunk[pos_delimiter_length:pos_delimiter_length+2] == "\r\n":
                            end_index = pos_delimiter_length + 2
                        elif chunk[pos_delimiter_length:pos_delimiter_length+1] == "\n":
                            end_index = pos_delimiter_length + 1
                        yield buffer + chunk[:start_index]
                        chunk = chunk[end_index:]
                        buffer = chunk
                    else:
                        buffer += chunk
                        break
                if not chunk:
                    yield buffer
                    break

    def read_text(self, params):
        """Read text file and return iterator for assembled HTTP requests

        Args:
            params (dict): input parameters
                "input" : input text filename
                "http_filter": HTTP packet filter
                "delimiter": requests delimiter (%--% by default)
                "fix_incomplete": use requests with incomplete body
                                  and fix content-length header
        """

        self.info = OrderedDict()
        self.info['total'] = 0
        self.info['complete'] = 0
        self.info['incorrect'] = 0
        self.info['incomplete'] = 0

        if 'fix_incomplete' not in params:
            params['fix_incomplete'] = False
        if 'input' not in params or not params['input']:
            raise ValueError('input filename is not specified or empty')
        if 'delimiter' in params and params['delimiter'] is not None:
            self.delimiter = params['delimiter']

        if "http_filter" not in params:
            params['http_filter'] = None
        for request in self.read_records(params['input'], self.delimiter):
            # HTTP request
            if self.parser.starts_with_http_method(request):
                self.info['total'] = self.info['total'] + 1
            # the next packet
            else:
                continue
            http_request = self.parser.parse_request(
                request, params['fix_incomplete'])
            if http_request is None:
                self.info['incorrect'] = self.info['incorrect'] + 1
                continue
            http_request['origin'] = self.parser.build_origin(http_request)

            if not self.parser.is_complete_request(http_request):
                if not params['fix_incomplete']:
                    continue
            else:
                self.info['complete'] = self.info['complete'] + 1
            http_request_packet = HTTPRequest(http_request)
            if not self.filter_http_packet(
                params['http_filter'],
                http_request_packet
            ):
                continue
            yield http_request_packet

        self.info['incomplete'] = self.info['total'] - \
            self.info['complete'] - self.info['incorrect']

    def filter_http_packet(self, filter_string, http):
        """Filter HTTP packet
        Args:
            filter_string (string): Packet filter
            http (HTTPRequest): extended dpkt HTTP packet

        Returns:
            bool: returns True if HTTP packet
                  is corresponding filter expression
        """

        if filter_string is not None and filter_string:
            return eval(filter_string)
        return True


class PcapParser:
    """HTTP requests iterator for pcap-file"""

    def __init__(self):
        """Constructor"""

        self.info = OrderedDict()
        self.info['total'] = 0
        self.info['complete'] = 0
        self.info['incorrect'] = 0
        self.info['incomplete'] = 0
        self.parser = HTTPParser()

    def read_pcap(self, params):
        """Read pcap-file and return iterator for assembled HTTP requests

        Args:
            params (dict): input parameters
                "input" : input pcap filename
                "filter": TCP/IP packet filter
                "http_filter": HTTP packet filter
        """

        self.info = OrderedDict()
        self.info['total'] = 0
        self.info['complete'] = 0
        self.info['incorrect'] = 0
        self.info['incomplete'] = 0

        if 'input' not in params or not params['input']:
            raise ValueError('input filename is not specified or empty')
        input_file_handler = open(params['input'], 'rb')
        try:
            pcap = dpkt.pcap.Reader(input_file_handler)
        except ValueError or OSError:
            try:
                pcap = dpkt.pcapng.Reader(input_file_handler)
            except ValueError:
                print("UPS: Unexpected pcap file format")
                print("Try to convert file with \"" +
                      "mergecap %s -w out.pcap -F pcap\"\n" % params['input'])
                raise

        streams = dict()
        if "filter" in params:
            params['filter'] = self.prepare_filter(params['filter'])
        else:
            params['filter'] = None
        if "http_filter" not in params:
            params['http_filter'] = None

        for timestamp, packet in pcap:
            try:
                eth_packet = dpkt.ethernet.Ethernet(packet)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                continue
            ip_packet = eth_packet.data
            if not hasattr(ip_packet, 'data'):
                continue
            if isinstance(ip_packet.data, UDP):
                continue
            tcp_packet = ip_packet.data
            if not hasattr(tcp_packet, 'data'):
                continue
            tcp_packet.data = tcp_packet.data.decode("utf-8", "replace")

            # remove cache on new or final packets
            if self.tcp_flags(tcp_packet.flags) in ("S", "R", "F"):
                if tcp_packet.sport in streams:
                    self.info['incomplete'] = self.info['incomplete'] + 1
                    del streams[tcp_packet.sport]
                continue
            # filter tcp packets
            # not empty
            if tcp_packet.data == '':
                continue
            # check filter
            if not self.filter_packet(
                params['filter'],
                eth_packet,
                ip_packet,
                tcp_packet
            ):
                continue
            # HTTP request
            if self.parser.starts_with_http_method(tcp_packet.data):
                self.info['total'] = self.info['total'] + 1
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
                http_request = self.parser.parse_request(
                    streams[tcp_packet.sport]['data']
                )
                if http_request is None:
                    self.info['incorrect'] = self.info['incorrect'] + 1
                    del streams[tcp_packet.sport]
                    continue
                http_request['origin'] = \
                    streams[tcp_packet.sport]['data']
                http_request['timestamp'] = \
                    streams[tcp_packet.sport]['timestamp']
                if not self.parser.is_complete_request(http_request):
                    continue
                self.info['complete'] = self.info['complete'] + 1
                del streams[tcp_packet.sport]
                http_request['src'] = socket.inet_ntoa(ip_packet.src)
                http_request['dst'] = socket.inet_ntoa(ip_packet.dst)
                http_request['sport'] = tcp_packet.sport
                http_request['dport'] = tcp_packet.dport
                http_request_packet = HTTPRequest(http_request)
                if not self.filter_http_packet(
                    params['http_filter'],
                    http_request_packet
                ):
                    continue
                yield http_request_packet

        self.info['incomplete'] = self.info['incomplete'] + len(streams)
        input_file_handler.close()

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
                r'(ip.(?:src|dst).*?)(["\"]?[\d\.]+["\"]?)',
                element
            )
            if match:
                return "%ssocket.inet_aton('%s')" % \
                    (match.group(1), match.group(2))
            return element

        if filter_string:
            return re.sub(
                r'(ip.(?:src|dst).*?)(["\"]?[\d\.]+["\"]?)',
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

        if filter_string is not None and filter_string:
            return eval(filter_string)
        return True

    def filter_http_packet(self, filter_string, http):
        """Filter HTTP packet
        Args:
            filter_string (string): Packet filter
            http (HTTPRequest): extended dpkt HTTP packet

        Returns:
            bool: returns True if HTTP packet
                  is corresponding filter expression
        """

        if filter_string is not None and filter_string:
            return eval(filter_string)
        return True

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


class HarParser:
    """HTTP requests iterator for har-file"""

    def __init__(self):
        """Constructor"""

        self.info = OrderedDict()
        self.info['total'] = 0
        self.info['complete'] = 0
        self.info['incorrect'] = 0
        self.info['incomplete'] = 0
        self.parser = HTTPParser()
        self.METHODS = dpkt.http.Request._Request__methods

    def read_har(self, params):
        """Read har-file and return iterator for HTTP requests

        Args:
            params (dict): input parameters
                "input" : input pcap filename
                "filter": TCP/IP packet filter
                "http_filter": HTTP packet filter
        """

        self.info = OrderedDict()
        self.info['total'] = 0
        self.info['complete'] = 0
        self.info['incorrect'] = 0
        self.info['incomplete'] = 0
        http_request = {}

        if 'input' not in params or not params['input']:
            raise ValueError('input filename is not specified or empty')
        file_handler = open(params['input'], 'r')
        data = json.load(file_handler)
        file_handler.close()
        if not('log' in data and 'entries' in data['log']):
            raise ValueError('incorrect har-file format')
        if "http_filter" not in params:
            params['http_filter'] = None
        for entry in data['log']['entries']:
            if 'request' not in entry:
                self.info['incorrect'] = self.info['incorrect'] + 1
                continue
            if 'httpVersion' not in entry['request']:
                http_request['version'] = '0.9'
            else:
                if not entry['request']['httpVersion'].startswith('HTTP/'):
                    http_request['version'] = '0.9'
                else:
                    http_request['version'] = \
                        entry['request']['httpVersion'].split('/')[1]
            if 'url' not in entry['request']:
                self.info['incorrect'] = self.info['incorrect'] + 1
                continue
            http_request['uri'] = entry['request']['url']
            if 'method' not in entry['request']:
                self.info['incorrect'] = self.info['incorrect'] + 1
                continue
            http_request['method'] = entry['request']['method']
            if 'headers' in entry['request']:
                http_request['headers'] = OrderedDict()
                http_request['origin_headers'] = OrderedDict()
                for pair in entry['request']['headers']:
                    http_request['origin_headers'][pair['name']] = \
                        pair['value']
                    http_request['headers'][pair['name'].lower()] = \
                        pair['value']
            if 'postData' in entry['request']:
                if 'text' not in entry['request']['postData']:
                    continue
                http_request['body'] = \
                    entry['request']['postData']['text']
            if 'startedDateTime' in entry:
                timestamp = date_parser.parse(
                    entry['startedDateTime'],
                    ignoretz=True
                )
                http_request['timestamp'] = \
                    (timestamp - datetime(1970, 1, 1)).total_seconds()
            # src is absent
            # src port is absent
            if 'serverIPAddress' in entry:
                http_request['dst'] = entry['serverIPAddress']
            # dst port is absent
            http_request["origin"] = \
                self.parser.build_origin(http_request)
            http_request_packet = HTTPRequest(http_request)
            if not self.filter_http_packet(
                params['http_filter'],
                http_request_packet
            ):
                continue
            self.info['total'] = self.info['total'] + 1
            self.info['complete'] = self.info['complete'] + 1
            yield http_request_packet

    def filter_http_packet(self, filter_string, http):
        """Filter HTTP packet
        Args:
            filter_string (string): Packet filter
            http (HTTPRequest): extended dpkt HTTP packet

        Returns:
            bool: returns True if HTTP packet
                  is corresponding filter expression
        """

        if filter_string is not None and filter_string:
            return eval(filter_string)
        return True

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
