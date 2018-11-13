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
from pcaper import parse_http
import pcaper
import sys
import socket


class TestParseHttp(object):

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
        """Prepare data file decorator"""

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
        """Remove data file decorator"""

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

    # Tests

    @pytest.mark.positive
    def test_parse_http_version(self, capsys):
        """Check version output"""

        with pytest.raises(SystemExit) as system_exit:
            sys.argv.append('-v')
            parse_http.main()
            sys.argv.remove('-v')
        assert system_exit.value.code == 0
        captured = capsys.readouterr()
        # for python2 captured.err
        # for python3 captured.out
        assert captured.err == pcaper.__version__ + "\n" or \
            captured.out == pcaper.__version__ + "\n", "unexpected output"

    @pytest.mark.positive
    def test_parse_http_input_file(
        self,
        prepare_data_file,
        capsys
    ):
        """Check main function parse input file correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        ethernet = self.generate_custom_http_request_packet(http_request)
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_data_file(data)
        parse_http.parse_http({
            'input': filename,
            'output': False,
            'stats': False,
            'stats_only': False,
            'filter': None,
        })
        captured = capsys.readouterr()
        assert captured.out == \
            "1489136209.000001: [10.10.10.1:40318 -> 10.10.10.2:8888]\n" + \
            http_request + "\n", "unexpected output"

    @pytest.mark.positive
    def test_parse_http_filter(
        self,
        prepare_data_file,
        capsys
    ):
        """Check main function parse input file with filter correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        params = {
            'ip': {
                'src': socket.inet_aton('10.4.0.136')
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

        # match filter
        parse_http.parse_http({
            'input': filename,
            'output': False,
            'stats': False,
            'stats_only': False,
            'filter': 'ip.src == 10.4.0.136',
        })
        captured = capsys.readouterr()
        assert captured.out == \
            "1489136209.000001: [10.4.0.136:40318 -> 10.10.10.2:8888]\n" + \
            http_request + "\n", "unexpected output"

        # unmatch filter
        parse_http.parse_http({
            'input': filename,
            'output': False,
            'stats': False,
            'stats_only': False,
            'filter': 'ip.src == 10.4.1.136',
        })
        captured = capsys.readouterr()
        assert captured.out == "", "unexpected output"

    @pytest.mark.positive
    def test_parse_http_output_file(
        self,
        prepare_data_file,
        capsys
    ):
        """Check parse_http write result in output file correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        ethernet = self.generate_custom_http_request_packet(http_request)
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_data_file(data)
        parse_http.parse_http({
            'input': filename,
            'output': 'test.out',
            'stats': False,
            'stats_only': False,
            'filter': None,
        })
        captured = capsys.readouterr()
        assert captured.out == "", "output is not empty"
        file_content = open('test.out', 'rb').read().decode("utf-8")
        assert file_content == \
            "1489136209.000001: [10.10.10.1:40318 -> 10.10.10.2:8888]\n" + \
            http_request + "\n", "unexpected output"
        os.remove('test.out')

    @pytest.mark.positive
    def test_parse_http_stats_only(
        self,
        prepare_data_file,
        capsys
    ):
        """Check stats-only flag handled correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        ethernet = self.generate_custom_http_request_packet(http_request)
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_data_file(data)
        parse_http.parse_http({
            'input': filename,
            'output': False,
            'stats': False,
            'stats_only': True,
            'filter': None,
        })
        captured = capsys.readouterr()
        assert captured.out == \
            "Stats:\n\ttotal: 1\n\tcomplete: 1\n\t" + \
            "incorrect: 0\n\tincomplete: 0\n", "unexpected output"

    @pytest.mark.positive
    def test_parse_http_stats(
        self,
        prepare_data_file,
        capsys
    ):
        """Check stats flag handled correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        ethernet = self.generate_custom_http_request_packet(http_request)
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_data_file(data)
        parse_http.parse_http({
            'input': filename,
            'output': False,
            'stats': True,
            'stats_only': False,
            'filter': None,
        })
        captured = capsys.readouterr()
        assert captured.out == \
            "1489136209.000001: [10.10.10.1:40318 -> 10.10.10.2:8888]\n" + \
            http_request + "\n" + \
            "Stats:\n\ttotal: 1\n\tcomplete: 1\n\t" + \
            "incorrect: 0\n\tincomplete: 0\n", "unexpected output"

    @pytest.mark.negative
    def test_parse_http_empty_input_file(
        self,
        capsys
    ):
        """Check empty input filename"""

        with pytest.raises(ValueError) as e:
            parse_http.parse_http({
                'input': None,
                'output': False,
                'stats': False,
                'stats_only': False,
                'filter': None,
            })
        assert e.value.args[0] == 'input filename is not specified or empty'
