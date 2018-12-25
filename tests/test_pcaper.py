#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2018 Alexander Grechin
#
# Licensed under the BSD 3-Clause license.
# See LICENSE file in the project root for full license information.
#

import os
import pytest
import tempfile
import dpkt
import pcaper
import socket


class TestPcaper(object):

    # Fixtures

    def set_pcap_file(self, filename, data):
        """Prepare pcap file"""

        file_handler = open(filename, "wb")
        pcap_file = dpkt.pcap.Writer(file_handler)
        for packet in data:
            pcap_file.writepkt(packet['data'], packet['timestamp'])
        file_handler.close()

    @pytest.fixture()
    def prepare_data_file(self):
        """Prepare data file decoraotor"""

        filename = {'file': ''}

        def _generate_temp_file(*args, **kwargs):
            filename['file'] = tempfile.NamedTemporaryFile(delete=False).name
            self.set_pcap_file(filename['file'], args[0])
            return filename['file']

        yield _generate_temp_file

        # remove file after test
        if os.path.isfile(filename['file']):
            os.remove(filename['file'])

    @pytest.fixture()
    def remove_data_file(self, request):
        """Remove data file decoraotor"""

        filename = {'file': ''}

        def _return_filename(*args, **kwargs):
            filename['file'] = tempfile.NamedTemporaryFile(delete=False) \
                .name
            return filename['file']

        yield _return_filename

        # remove file after test
        if os.path.isfile(filename['file']):
            os.remove(filename['file'])

    # Additional methods

    def replace_params(self, ethernet, params=[]):
        if 'tcp' in params:
            for field in params['tcp']:
                setattr(ethernet.data.data, field, params['tcp'][field])
        if 'ip' in params:
            for field in params['ip']:
                setattr(ethernet.data, field, params['ip'][field])
        if 'ethernet' in params:
            for field in params['ethernet']:
                setattr(ethernet, field, params['ethernet'][field])

    def generate_custom_http_request_packet(self, data, params=[]):
        tcp = dpkt.tcp.TCP(
            b'\x9d\x7e' +                                        # sport
            b'\x22\xb8' +                                        # dport
            b'\xb6\xce\xe8\x3d' +                                # seq
            b'\xb7\x1a\x15\x40' +                                # ack
            b'\x80' +                                            # len
            b'\x18' +                                            # flags
            b'\x0e\x42' +                                        # win
            b'\x40\xe0' +                                        # chk
            b'\x00\x00' +                                        # pointer
            b'\x01\x01\x08\x0a\x3c\x58\x15\xa4\x90\xfd\xa6\xc4'  # options
        )
        tcp.data = data.encode("utf-8")
        ip = dpkt.ip.IP(
            b'\x45' +              # ver + hlen
            b'\x00' +              # dsf
            b'\x04\x24' +          # len
            b'\xfd\xa1' +          # id
            b'\x40' +              # flags
            b'\x00' +              # offset
            b'\x40' +              # ttl
            b'\x06' +              # proto
            b'\xfc\x68' +          # cks
            b'\x0a\x0a\x0a\x01' +  # src
            b'\x0a\x0a\x0a\x02'    # dst
        )
        ip.len = len(data)
        ip.data = tcp
        ethernet = dpkt.ethernet.Ethernet(
            b'\x00\x00\x00\x00\x00\x02' +  # dmac
            b'\x00\x00\x00\x00\x00\x01' +  # smac
            b'\x08\x00'
        )
        ethernet.data = ip
        self.replace_params(ethernet, params)
        return ethernet

    def generate_syn_packet(self):
        tcp = dpkt.tcp.TCP(
            b'\x9d\x7e\x22\xb8\xb6\xce\xe8\x3c\x00\x00\x00\x00' +
            b'\xa0\x02\x72\x10\x3c\xf8\x00\x00\x02\x04\x05\xb4' +
            b'\x04\x02\x08\x0a\x3c\x58\x15\xa3\x00\x00\x00\x00' +
            b'\x01\x03\x03\x03'
        )
        ip = dpkt.ip.IP(
            b'\x45\x00\x00\x3c\xfd\x9f\x40\x00\x40\x06\x00\x53' +
            b'\x0a\x0a\x0a\x01' +  # src
            b'\x0a\x0a\x0a\x02'    # dst
        )
        ip.data = tcp
        ethernet = dpkt.ethernet.Ethernet(
            b'\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x01\x08\x00'
        )
        ethernet.data = ip
        return ethernet

    def generate_synack_packet(self):
        tcp = dpkt.tcp.TCP(
            b'\x22\xb8\x9d\x7e\xb7\x1a\x15\x3f\xb6\xce\xe8\x3d' +
            b'\xa0\x12\x71\x20\xe4\xa9\x00\x00\x02\x04\x05\xb4' +
            b'\x04\x02\x08\x0a\x90\xfd\xa6\xc4\x3c\x58\x15\xa3' +
            b'\x01\x03\x03\x09'
        )
        ip = dpkt.ip.IP(
            b'\x45\x00\x00\x3c\x00\x00\x40\x00\x3e\x06\xff\xf2' +
            b'\x0a\x0a\x0a\x02' +
            b'\x0a\x0a\x0a\x01'
        )
        ip.data = tcp
        ethernet = dpkt.ethernet.Ethernet(
            b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x02\x08\x00'
        )
        ethernet.data = ip
        return ethernet

    def generate_ack_packet(self):
        tcp = dpkt.tcp.TCP(
            b'\x9d\x7e\x22\xb8\xb6\xce\xe8\x3d\xb7\x1a\x15\x40' +
            b'\x80\x10\x0e\x42\x3c\xf0\x00\x00\x01\x01\x08\x0a' +
            b'\x3c\x58\x15\xa4\x90\xfd\xa6\xc4'
        )
        ip = dpkt.ip.IP(
            b'\x45\x00\x00\x34\xfd\xa0\x40\x00\x40\x06\x00\x5a' +
            b'\x0a\x0a\x0a\x01' +
            b'\x0a\x0a\x0a\x02'
        )
        ip.data = tcp
        ethernet = dpkt.ethernet.Ethernet(
            b'\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x01\x08\x00'
        )
        ethernet.data = ip
        return ethernet

    def generate_http_request_packet(self, data):
        tcp = dpkt.tcp.TCP(
            b'\x9d\x7e\x22\xb8\xb6\xce\xe8\x3d\xb7\x1a\x15\x40' +
            b'\x80\x18\x0e\x42\x40\xe0\x00\x00\x01\x01\x08\x0a' +
            b'\x3c\x58\x15\xa4\x90\xfd\xa6\xc4'
        )
        try:
            tcp.data = bytes(data)
        except TypeError:
            tcp.data = bytes(data, "utf-8")
        ip = dpkt.ip.IP(
            b'\x45\x00\x04\x24\xfd\xa1\x40\x00\x40\x06\xfc\x68' +
            b'\x0a\x0a\x0a\x01' +
            b'\x0a\x0a\x0a\x02'
        )
        ip.len = len(data)
        ip.data = tcp
        ethernet = dpkt.ethernet.Ethernet(
            b'\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x01\x08\x00'
        )
        ethernet.data = ip
        return ethernet

    def generate_ack_after_request_packet(self):
        tcp = dpkt.tcp.TCP(
            b'\x22\xb8\x9d\x7e\xb7\x1a\x15\x40\xb6\xce\xe8\x86' +
            b'\x80\x10\x00\x3d\x80\x6a\x00\x00\x01\x01\x08\x0a' +
            b'\x90\xfd\xa6\xc4\x3c\x58\x15\xa4'
        )
        ip = dpkt.ip.IP(
            b'\x45\x00\x00\x34\xb3\x84\x40\x00\x3e\x06\x4c\x76' +
            b'\x0a\x0a\x0a\x02' +
            b'\x0a\x0a\x0a\x01'
        )
        ip.data = tcp
        ethernet = dpkt.ethernet.Ethernet(
            b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x02\x08\x00'
        )
        ethernet.data = ip
        return ethernet

    def generate_http_response_packet(self, data):
        tcp = dpkt.tcp.TCP(
            b'\x22\xb8\x9d\x7e\xb7\x1a\x15\x40\xb6\xce\xe8\x86' +
            b'\x80\x18\x00\x3d\x46\xbf\x00\x00\x01\x01\x08\x0a' +
            b'\x90\xfd\xa6\xcf\x3c\x58\x15\xa4'
        )
        tcp.data = data.encode("utf-8")
        ip = dpkt.ip.IP(
            b'\x45\x00\x0a\x03\xb3\x85\x40\x00\x3e\x06\x42\xa6' +
            b'\x0a\x0a\x0a\x02' +
            b'\x0a\x0a\x0a\x01'
        )
        ip.len = len(data)
        ip.data = tcp
        ethernet = dpkt.ethernet.Ethernet(
            b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x02\x08\x00'
        )
        ethernet.data = ip
        return ethernet

    def generate_ack_after_response_packet(self):
        tcp = dpkt.tcp.TCP(
            b'\x9d\x7e\x22\xb8\xb6\xce\xe8\x86\xb7\x1a\x15\x53' +
            b'\x80\x10\x54\xa0\x3c\xf0\x00\x00\x01\x01\x08\x0a' +
            b'\x3c\x58\x15\xd2\x90\xfd\xa6\xd2'
        )
        ip = dpkt.ip.IP(
            b'\x45\x00\x00\x34\xfd\xe9\x40\x00\x40\x06\x00\x11' +
            b'\x0a\x0a\x0a\x01' +
            b'\x0a\x0a\x0a\x02'
        )
        ip.data = tcp
        ethernet = dpkt.ethernet.Ethernet(
            b'\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x01\x08\x00'
        )
        ethernet.data = ip
        return ethernet

    def generate_first_fin_packet(self):
        tcp = dpkt.tcp.TCP(
            b'\x9d\x7e\x22\xb8\xb6\xce\xe8\x86\xb7\x1a\x15\x53' +
            b'\x80\x11\x54\xa0\x3c\xf0\x00\x00\x01\x01\x08\x0a' +
            b'\x3c\x58\x15\xd2\x90\xfd\xa6\xd2'
        )
        ip = dpkt.ip.IP(
            b'\x45\x00\x00\x34\xfd\xea\x40\x00\x40\x06\x00\x10' +
            b'\x0a\x0a\x0a\x01' +
            b'\x0a\x0a\x0a\x02'
        )
        ip.data = tcp
        ethernet = dpkt.ethernet.Ethernet(
            b'\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x01\x08\x00'
        )
        ethernet.data = ip
        return ethernet

    def generate_second_fin_packet(self):
        tcp = dpkt.tcp.TCP(
            b'\x22\xb8\x9d\x7e\xb7\x1a\x15\x53\xb6\xce\xe8\x87' +
            b'\x80\x11\x00\x3d\x53\x05\x00\x00\x01\x01\x08\x0a' +
            b'\x90\xfd\xa6\xd2\x3c\x58\x15\xd2'
        )
        ip = dpkt.ip.IP(
            b'\x45\x00\x00\x34\xb4\x46\x40\x00\x3e\x06\x4b\xb4' +
            b'\x0a\x0a\x0a\x01' +
            b'\x0a\x0a\x0a\x02'
        )
        ip.data = tcp
        ethernet = dpkt.ethernet.Ethernet(
            b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x02\x08\x00'
        )
        ethernet.data = ip
        return ethernet

    def generate_ack_after_second_fin_packet(self):
        tcp = dpkt.tcp.TCP(
            b'\x9d\x7e\x22\xb8\xb6\xce\xe8\x87\x7e\xb7\x1a\x16' +
            b'\x80\x10\x54\xa0\x3c\xf0\x00\x00\x01\x01\x08\x0a' +
            b'\x3c\x58\x15\xd4\x90\xfd\xa6\xd2'
        )
        ip = dpkt.ip.IP(
            b'\x45\x00\x00\x34\xfd\xeb\x40\x00\x40\x06\x00\x0f' +
            b'\x0a\x0a\x0a\x02' +
            b'\x0a\x0a\x0a\x01'
        )
        ip.data = tcp
        ethernet = dpkt.ethernet.Ethernet(
            b'\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x01\x08\x00'
        )
        ethernet.data = ip
        return ethernet

    def generate_tcp_session(self, http_request, http_response):
        data = [
            {
                'timestamp': 1489136209.000001,
                'data': self.generate_syn_packet().__bytes__()
            },
            {
                'timestamp': 1489136209.000002,
                'data': self.generate_synack_packet().__bytes__()
            },
            {
                'timestamp': 1489136209.000003,
                'data': self.generate_ack_packet().__bytes__()
            },
            {
                'timestamp': 1489136209.000004,
                'data': self.generate_http_request_packet(
                    http_request
                ).__bytes__()
            },
            {
                'timestamp': 1489136209.000005,
                'data': self.generate_ack_after_request_packet().__bytes__()
            },
            {
                'timestamp': 1489136209.000006,
                'data': self.generate_http_response_packet(
                    http_response
                ).__bytes__()
            },
            {
                'timestamp': 1489136209.000007,
                'data': self.generate_ack_after_response_packet().__bytes__()
            },
            {
                'timestamp': 1489136209.000008,
                'data': self.generate_first_fin_packet().__bytes__()
            },
            {
                'timestamp': 1489136209.000009,
                'data': self.generate_second_fin_packet().__bytes__()
            },
            {
                'timestamp': 1489136209.000010,
                'data': self.generate_ack_after_second_fin_packet().__bytes__()
            },
        ]
        return data

    # Tests

    @pytest.mark.positive
    def test_read_pcap_parse_http_get_request_with_content_length(
        self,
        prepare_data_file
    ):
        """Check pcap_reader parse http get request
        with content_length correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        ethernet = self.generate_http_request_packet(http_request)
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_data_file(data)
        reader = pcaper.HTTPRequest()

        packets = 0
        for request in reader.read_pcap({
            'input': filename
            }
        ):
            assert request['origin'] == http_request, \
                "unexpected http request data"
            packets = packets + 1
        assert packets == 1, "unexpected packets count"

    @pytest.mark.negative
    def test_read_pcap_parse_http_with_non_utf8_encoding(
        self,
        prepare_data_file
    ):
        """Check pcap_reader parse http data
        with non utf-8 encoding correctly"""

        http_request = "POST https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 3\r\n\r\n" + \
                       "\x89\r\n"
        try:
            expected_http_request = bytes(http_request)
        except TypeError:
            expected_http_request = bytes(http_request, "utf-8")
        expected_http_request = \
            expected_http_request.decode("utf-8", "replace")
        ethernet = self.generate_http_request_packet(http_request)
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_data_file(data)
        reader = pcaper.HTTPRequest()

        packets = 0
        for request in reader.read_pcap({
            'input': filename
            }
        ):
            assert request['origin'] == expected_http_request, \
                "unexpected http request data"
            packets = packets + 1
        assert packets == 1, "unexpected packets count"

    @pytest.mark.positive
    def test_read_pcap_parse_http_get_request_without_content_length(
        self,
        prepare_data_file
    ):
        """Check pcap_reader parse http get request
        without content_length correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n\r\n"
        ethernet = self.generate_http_request_packet(http_request)
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_data_file(data)
        reader = pcaper.HTTPRequest()

        packets = 0
        for request in reader.read_pcap({
            'input': filename
            }
        ):
            assert request['origin'] == http_request, \
                "unexpected http request data"
            packets = packets + 1
        assert packets == 1, "unexpected packets count"

    @pytest.mark.negative
    def test_read_pcap_parse_empty_http_request(self, prepare_data_file):
        """Check pcap_reader parse empty http request correctly"""

        http_request = ""
        ethernet = self.generate_http_request_packet(http_request)
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_data_file(data)
        reader = pcaper.HTTPRequest()

        packets = 0
        for request in reader.read_pcap({
            'input': filename
            }
        ):
            assert request['origin'] == http_request, \
                "unexpected http request data"
            packets = packets + 1
        assert packets == 0, "unexpected packets count"

    @pytest.mark.positive
    def test_read_pcap_parse_http_post_request(self, prepare_data_file):
        """Check pcap_reader parse http post request correctly"""

        http_request = "POST https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n\r\n" + \
                       "param1=0\r\n"
        ethernet = self.generate_http_request_packet(http_request)
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_data_file(data)
        reader = pcaper.HTTPRequest()

        packets = 0
        for request in reader.read_pcap({
            'input': filename
            }
        ):
            assert request['origin'] == http_request, \
                "unexpected http request data"
            packets = packets + 1
        assert packets == 1, "unexpected packets count"

    @pytest.mark.positive
    def test_read_pcap_http_session(self, prepare_data_file):
        """Check pcap_reader reads http session"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        http_response = "HTTP/1.1 200 OK\r\n\r\n"
        data = self.generate_tcp_session(http_request, http_response)
        filename = prepare_data_file(data)
        reader = pcaper.HTTPRequest()

        packets = 0
        for request in reader.read_pcap({
            'input': filename
            }
        ):
            assert request['origin'] == http_request, \
                "unexpected http request data"
            packets = packets + 1
        assert packets == 1, "unexpected packets count"

    @pytest.mark.negative
    def test_read_pcap_only_http_response(self, prepare_data_file):
        """Check pcap_reader reads only http requests"""

        http_response = "HTTP/1.1 200 OK\r\n\r\n"
        ethernet = self.generate_http_response_packet(http_response)
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_data_file(data)
        reader = pcaper.HTTPRequest()

        packets = 0
        for request in reader.read_pcap({
            'input': filename
            }
        ):
            packets = packets + 1
        assert packets == 0, "unexpected packets count"

    @pytest.mark.positive
    def test_read_pcap_starts_with_http_method_is_true(self):
        """Check starts_with_http_method returns True
        if request starts with method"""

        reader = pcaper.HTTPRequest()
        for method in dpkt.http.Request._Request__methods:
            packet = ("%s https://rambler.ru/ HTTP/1.1\r\n" +
                      "Host: rambler.ru\r\n" +
                      "Content-Length: 0\r\n\r\n") % method
            assert reader.starts_with_http_method(packet) is True, \
                "request should start with method"

    @pytest.mark.positive
    def test_read_pcap_starts_with_http_method_is_false(self):
        """Check starts_with_http_method returns False
        if request starts with no method"""

        reader = pcaper.HTTPRequest()
        assert reader.starts_with_http_method("some string") is False, \
            "function should return False if not request"

    @pytest.mark.positive
    def test_read_pcap_http_request_with_filter_by_dport(
        self,
        prepare_data_file
    ):
        """Check pcap_reader filter packets by tcp.dport correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        params = {
            'tcp': {
                'dport': 80
            }
        }
        ethernet = self.generate_custom_http_request_packet(
            http_request,
            params
        )
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_data_file(data)
        reader = pcaper.HTTPRequest()

        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'filter': 'tcp.dport == 80'
            }
        ):
            assert request['origin'] == http_request, \
                "unexpected http request data"
            packets = packets + 1
        assert packets == 1, "unexpected packets count"

        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'filter': 'tcp.dport == 81'
            }
        ):
            packets = packets + 1
        assert packets == 0, "unexpected packets count"

    @pytest.mark.positive
    def test_read_pcap_http_request_with_exfilter_by_dport(
        self,
        prepare_data_file
    ):
        """Check pcap_reader excludes packets by tcp.dport correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        params = {
            'tcp': {
                'dport': 80
            }
        }
        ethernet = self.generate_custom_http_request_packet(
            http_request,
            params
        )
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_data_file(data)
        reader = pcaper.HTTPRequest()

        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'exfilter': 'tcp.dport == 80'
            }
        ):
            assert request['origin'] == http_request, \
                "unexpected http request data"
            packets = packets + 1
        assert packets == 0, "unexpected packets count"

        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'exclude-filter': 'tcp.dport == 81'
            }
        ):
            packets = packets + 1
        assert packets == 1, "unexpected packets count"

    @pytest.mark.positive
    def test_read_pcap_http_request_with_filter_by_src(
        self,
        prepare_data_file
    ):
        """Check pcap_reader filter packets by ip.src correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        params = {
            'ip': {
                'src': socket.inet_aton('1.1.1.1')
            }
        }
        ethernet = self.generate_custom_http_request_packet(
            http_request,
            params
        )
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_data_file(data)
        reader = pcaper.HTTPRequest()

        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'filter': 'ip.src == 1.1.1.1'
            }
        ):
            assert request['origin'] == http_request, \
                "unexpected http request data"
            packets = packets + 1
        assert packets == 1, "unexpected packets count"

        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'filter': 'ip.src == 1.1.1.2'
            }
        ):
            packets = packets + 1
        assert packets == 0, "unexpected packets count"

    @pytest.mark.positive
    def test_read_pcap_http_request_with_exfilter_by_src(
        self,
        prepare_data_file
    ):
        """Check pcap_reader excludes packets by ip.src correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        params = {
            'ip': {
                'src': socket.inet_aton('1.1.1.1')
            }
        }
        ethernet = self.generate_custom_http_request_packet(
            http_request,
            params
        )
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_data_file(data)
        reader = pcaper.HTTPRequest()

        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'exfilter': 'ip.src == 1.1.1.1'
            }
        ):
            assert request['origin'] == http_request, \
                "unexpected http request data"
            packets = packets + 1
        assert packets == 0, "unexpected packets count"

        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'exfilter': 'ip.src == 1.1.1.2'
            }
        ):
            packets = packets + 1
        assert packets == 1, "unexpected packets count"

    @pytest.mark.positive
    def test_read_pcap_http_request_with_filter_and_exfilter_by_src(
        self,
        prepare_data_file
    ):
        """Check pcap_reader excludes packets by ip.src correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        params1 = {
            'ip': {
                'src': socket.inet_aton('1.1.1.1')
            }
        }
        ethernet1 = self.generate_custom_http_request_packet(
            http_request,
            params1
        )
        params2 = {
            'ip': {
                'src': socket.inet_aton('1.1.1.2')
            }
        }
        ethernet2 = self.generate_custom_http_request_packet(
            http_request,
            params2
        )
        data = [
            {
                'timestamp': 1489136209.000001,
                'data': ethernet1.__bytes__()
            },
            {
                'timestamp': 1489136209.000002,
                'data': ethernet2.__bytes__()
            }
        ]
        filename = prepare_data_file(data)
        reader = pcaper.HTTPRequest()

        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'filter': 'ip.src == 1.1.1.1',
            'exfilter': 'ip.src == 1.1.1.2'
            }
        ):
            packets = packets + 1
            assert request['src'] == '1.1.1.1'
        assert packets == 1, "unexpected packets count"

        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'filter': 'ip.src == 1.1.1.2',
            'exfilter': 'ip.src == 1.1.1.1'
            }
        ):
            packets = packets + 1
            assert request['src'] == '1.1.1.2'
        assert packets == 1, "unexpected packets count"

        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'filter': 'ip.src == 1.1.1.2',
            'exfilter': 'ip.src == 1.1.1.2'
            }
        ):
            packets = packets + 1
        assert packets == 0, "unexpected packets count"

        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'filter': 'ip.src == 1.1.1.1',
            'exfilter': 'ip.src == 1.1.1.1'
            }
        ):
            packets = packets + 1
        assert packets == 0, "unexpected packets count"

        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'filter': 'ip.src == 1.1.1.3',
            'exfilter': 'ip.src == 1.1.1.3'
            }
        ):
            packets = packets + 1
        assert packets == 0, "unexpected packets count"

        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'filter': 'ip.src == 1.1.1.1 or ip.src == 1.1.1.2',
            'exfilter': 'ip.src == 1.1.1.2 or ip.src == 1.1.1.1'
            }
        ):
            packets = packets + 1
        assert packets == 0, "unexpected packets count"

    @pytest.mark.positive
    def test_read_pcap_http_request_with_filter_by_dport_or_src(
        self,
        prepare_data_file
    ):
        """Check pcap_reader filter packets by tcp.dport or ip.src correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        params1 = {
            'tcp': {
                'dport': 80
            },
            'ip': {
                'src': socket.inet_aton('1.1.1.2')
            }
        }
        ethernet1 = self.generate_custom_http_request_packet(
            http_request,
            params1
        )
        params2 = {
            'tcp': {
                'dport': 81
            },
            'ip': {
                'src': socket.inet_aton('1.1.1.1')
            }
        }
        ethernet2 = self.generate_custom_http_request_packet(
            http_request,
            params2
        )
        data = [
            {
                'timestamp': 1489136209.000001,
                'data': ethernet1.__bytes__()
            },
            {
                'timestamp': 1489136209.000002,
                'data': ethernet2.__bytes__()
            }
        ]
        filename = prepare_data_file(data)
        reader = pcaper.HTTPRequest()

        # tcp.dport == 80 or ip.src == 1.1.1.1
        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'filter': 'tcp.dport == 80 or ip.src == 1.1.1.1'
            }
        ):
            assert request['origin'] == http_request, \
                "unexpected http request data"
            packets = packets + 1
        assert packets == 2, "unexpected packets count"

        # tcp.dport == 82 or ip.src == 1.1.1.2
        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'filter': 'tcp.dport == 82 or ip.src == 1.1.1.2'
            }
        ):
            assert request['origin'] == http_request, \
                "unexpected http request data"
            packets = packets + 1
        assert packets == 1, "unexpected packets count"

        # tcp.dport == 82 or ip.src == 1.1.1.3
        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'filter': 'tcp.dport == 82 or ip.src == 1.1.1.3'
            }
        ):
            packets = packets + 1
        assert packets == 0, "unexpected packets count"

    @pytest.mark.positive
    def test_read_pcap_http_request_with_filter_by_dport_and_src(
        self,
        prepare_data_file
    ):
        """Check pcap_reader filter packets
        by tcp.dport and ip.src correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        params1 = {
            'tcp': {
                'dport': 80
            },
            'ip': {
                'src': socket.inet_aton('1.1.1.2')
            }
        }
        ethernet1 = self.generate_custom_http_request_packet(
            http_request,
            params1
        )
        params2 = {
            'tcp': {
                'dport': 81
            },
            'ip': {
                'src': socket.inet_aton('1.1.1.1')
            }
        }
        ethernet2 = self.generate_custom_http_request_packet(
            http_request,
            params2
        )
        data = [
            {
                'timestamp': 1489136209.000001,
                'data': ethernet1.__bytes__()
            },
            {
                'timestamp': 1489136209.000002,
                'data': ethernet2.__bytes__()
            }
        ]
        filename = prepare_data_file(data)
        reader = pcaper.HTTPRequest()

        # tcp.dport == 80 and ip.src == 1.1.1.2
        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'filter': 'tcp.dport == 80 and ip.src == 1.1.1.2'
            }
        ):
            assert request['origin'] == http_request, \
                "unexpected http request data"
            packets = packets + 1
        assert packets == 1, "unexpected packets count"

        # tcp.dport == 80 and ip.src == 1.1.1.3
        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'filter': 'tcp.dport == 80 and ip.src == 1.1.1.3'
            }
        ):
            packets = packets + 1
        assert packets == 0, "unexpected packets count"

        # tcp.dport == 82 and ip.src == 1.1.1.3
        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'filter': 'tcp.dport == 82 and ip.src == 1.1.1.3'
            }
        ):
            packets = packets + 1
        assert packets == 0, "unexpected packets count"

    @pytest.mark.positive
    def test_get_stats_check_stats(self, prepare_data_file):
        """Check get_stast method returns correct stats"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        ethernet = self.generate_http_request_packet(http_request)
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_data_file(data)
        reader = pcaper.HTTPRequest()
        local_stats = {
            "total": 0,
            "complete": 0,
            "incorrect": 0,
            "incomplete": 0,
        }
        reader_stats = reader.get_stats()
        for key in reader_stats.keys():
            assert key in local_stats, "unexpected key"
            assert reader_stats[key] == 0, "unexpected value"

        for request in reader.read_pcap({
            'input': filename
            }
        ):
            pass
        reader.get_stats()
        reader_stats = reader.get_stats()
        assert reader_stats['total'] == 1, "unexpected total value"
        assert reader_stats['complete'] == 1, "unexpected total value"
        assert reader_stats['incorrect'] == 0, "unexpected total value"
        assert reader_stats['incomplete'] == 0, "unexpected total value"

    @pytest.mark.negative
    def test_read_pcap_http_request_incomplete_request(
        self,
        prepare_data_file
    ):
        """Check pcap_reader handle incomplete requests correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n"
        ethernet = self.generate_http_request_packet(http_request)
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_data_file(data)
        reader = pcaper.HTTPRequest()

        packets = 0
        for request in reader.read_pcap({
            'input': filename
            }
        ):
            assert request['origin'] == http_request, \
                "unexpected http request data"
            packets = packets + 1
        assert packets == 0, "unexpected packets count"
        reader_stats = reader.get_stats()
        assert reader_stats['total'] == 1, "unexpected total value"
        assert reader_stats['complete'] == 0, "unexpected total value"
        assert reader_stats['incorrect'] == 0, "unexpected total value"
        assert reader_stats['incomplete'] == 1, "unexpected total value"

    @pytest.mark.negative
    def test_read_pcap_http_request_incorrect_request(self, prepare_data_file):
        """Check pcap_reader handle incorrect requests correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        ethernet = self.generate_http_request_packet(http_request)
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_data_file(data)
        reader = pcaper.HTTPRequest()

        packets = 0
        for request in reader.read_pcap({
            'input': filename
            }
        ):
            assert request['origin'] == http_request, \
                "unexpected http request data"
            packets = packets + 1
        assert packets == 0, "unexpected packets count"
        reader_stats = reader.get_stats()
        assert reader_stats['total'] == 1, "unexpected total value"
        assert reader_stats['complete'] == 0, "unexpected total value"
        assert reader_stats['incorrect'] == 1, "unexpected total value"
        assert reader_stats['incomplete'] == 0, "unexpected total value"

    @pytest.mark.negative
    def test_read_pcap_empty_filter(self, prepare_data_file):
        """Check pcap_reader read pcap with empty filter correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        ethernet = self.generate_http_request_packet(http_request)
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_data_file(data)
        reader = pcaper.HTTPRequest()

        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'filter': ''
            }
        ):
            assert request['origin'] == http_request, \
                "unexpected http request data"
            packets = packets + 1
        assert packets == 1, "unexpected packets count"

    @pytest.mark.negative
    def test_read_pcap_parse_http_incorrect_post_request(
        self,
        prepare_data_file
    ):
        """Check pcap_reader parse incorrect http post request
         without exception"""

        http_request = "POST https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 12\r\n\r\n" + \
                       "param1=0\r\n"
        ethernet = self.generate_http_request_packet(http_request)
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_data_file(data)
        reader = pcaper.HTTPRequest()

        packets = 0
        for request in reader.read_pcap({
            'input': filename
            }
        ):
            assert request['origin'] == http_request, \
                "unexpected http request data"
            packets = packets + 1
        assert packets == 0, "unexpected packets count"
        reader_stats = reader.get_stats()
        assert reader_stats['total'] == 1, "unexpected total value"
        assert reader_stats['complete'] == 0, "unexpected total value"
        assert reader_stats['incorrect'] == 1, "unexpected total value"
        assert reader_stats['incomplete'] == 0, "unexpected total value"

    @pytest.mark.positive
    def test_read_pcap_parse_pcapng_format(self, capsys, remove_data_file):
        """Check pcap_reader handle pcapng format exception"""

        reader = pcaper.HTTPRequest()

        packets = 0
        filename = remove_data_file()
        file_handler = open(filename, "wb")
        file_handler.write(
            b'\x0a\x0d\x0d\x0a\x88\x00\x00\x00\x4d\x3c\x2b\x1a\x01\x00\x00' +
            b'\x00\xff\xff\xff\xff\xff\xff\xff\xff\x03\x00\x2d\x00\x4d\x61' +
            b'\x63\x20\x4f\x53\x20\x58\x20\x31\x30\x2e\x31\x33\x2e\x33\x2c' +
            b'\x20\x62\x75\x69\x6c\x64\x20\x31\x37\x44\x34\x37\x20\x28\x44' +
            b'\x61\x72\x77\x69\x6e\x20\x31\x37\x2e\x34\x2e\x30\x29\x00\x00' +
            b'\x00\x04\x00\x2d\x00\x44\x75\x6d\x70\x63\x61\x70\x20\x28\x57' +
            b'\x69\x72\x65\x73\x68\x61\x72\x6b\x29\x20\x32\x2e\x32\x2e\x32' +
            b'\x20\x28\x76\x32\x2e\x32\x2e\x32\x2d\x30\x2d\x67\x37\x37\x35' +
            b'\x66\x62\x30\x38\x29\x00\x00\x00\x00\x00\x00\x00\x88\x00\x00' +
            b'\x00\x01\x00\x00\x00\x5c\x00\x00\x00\x01\x00\x00\x00\x00\x00' +
            b'\x04\x00\x02\x00\x03\x00\x65\x6e\x30\x00\x09\x00\x01\x00\x06' +
            b'\x00\x00\x00\x0c\x00\x2d\x00\x4d\x61\x63\x20\x4f\x53\x20\x58' +
            b'\x20\x31\x30\x2e\x31\x33\x2e\x33\x2c\x20\x62\x75\x69\x6c\x64' +
            b'\x20\x31\x37\x44\x34\x37\x20\x28\x44\x61\x72\x77\x69\x6e\x20' +
            b'\x31\x37\x2e\x34\x2e\x30\x29\x00\x00\x00\x00\x00\x00\x00\x5c' +
            b'\x00\x00\x00\x06\x00\x00\x00\x58\x00\x00\x00\x00\x00\x00\x00' +
            b'\xc5\x78\x05\x00\xd5\x79\xf9\xc8\x36\x00\x00\x00\x36\x00\x00' +
            b'\x00\x00' +
            b'\x19\xcb\x58\xe8\x47\x9c\xf3\x87\xa2\x0c\x92\x08\x00\x45\x00' +
            b'\x00\x28\x65\x79\x00\x00\x40\x06\x85\x50\xc0\xa8\x01\x25\x4a' +
            b'\x7d\x83\xbc\xe5\xd2\x01\xbb\xf8\x67\xe8\xae\xda\xa9\x7f\xde' +
            b'\x50\x10\x10\x00\xec\xa0\x00\x00' +
            b'\x00\x00\x58\x00\x00\x00')

        file_handler.close()

        # check exception text
        with pytest.raises(
                ValueError, match=r'invalid pcapng header: not a SHB'):
            packets = 0
            for request in reader.read_pcap({
                'input': filename
                }
            ):
                packets = packets + 1
        captured = capsys.readouterr()
        assert packets == 0, "unexpected packets count"
        assert captured.out.startswith("UPS: Unexpected pcap file format")
