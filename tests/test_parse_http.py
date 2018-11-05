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
        ethernet = self.generate_http_request_packet(http_request)
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
    def test_parse_http_output_file(
        self,
        prepare_data_file,
        capsys
    ):
        """Check parse_http write result in output file correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        ethernet = self.generate_http_request_packet(http_request)
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
        ethernet = self.generate_http_request_packet(http_request)
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
        ethernet = self.generate_http_request_packet(http_request)
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
