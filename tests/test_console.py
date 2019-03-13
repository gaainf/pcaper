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
import subprocess
from pcaper import pcap_gen
from pcaper import har_gen
import json


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
    def prepare_pcap_file(self):
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

    def set_har_file(self, filename, data):
        """Prepare har file"""

        file_handler = open(filename, "w")
        json.dump(data, file_handler)
        file_handler.close()

    @pytest.fixture()
    def prepare_har_file(self):
        """Prepare har file decorator"""

        filename = {'file': ''}

        def _generate_temp_file(*args, **kwargs):
            filename['file'] = tempfile.NamedTemporaryFile(delete=False).name
            self.set_har_file(filename['file'], args[0])
            return filename['file']

        yield _generate_temp_file

        # remove file after test
        if os.path.isfile(filename['file']):
            os.remove(filename['file'])

    # Tests
    # pcap2txt

    @pytest.mark.positive
    def test_pcap2txt_version(self):
        """Check version output"""

        command = ['pcap2txt', '-v']
        output = subprocess.check_output(
            command, stderr=subprocess.STDOUT
        ).decode()
        assert output == pcaper.__version__ + "\n", "unexpected output"

    @pytest.mark.positive
    def test_pcap2txt_input_file(
        self,
        prepare_pcap_file
    ):
        """Check pcap2txt parse input file correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        ethernet = pcap_gen.generate_http_request_packet(http_request)
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_pcap_file(data)
        command = ['pcap2txt', filename]
        output = subprocess.check_output(
            command, stderr=subprocess.STDOUT
        ).decode()
        assert output == \
            "1489136209.000001: [10.10.10.1:40318 -> 10.10.10.2:8888]\n" + \
            http_request + "\n", "unexpected output"

    @pytest.mark.positive
    def test_pcap2txt_output_file(
        self,
        prepare_pcap_file
    ):
        """Check pcap2txt write result in output file correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        ethernet = pcap_gen.generate_http_request_packet(http_request)
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_pcap_file(data)
        command = ['pcap2txt', '-o', 'test.out', filename]
        output = subprocess.check_output(
            command, stderr=subprocess.STDOUT
        ).decode()
        assert output == "", "output is not empty"
        file_content = open('test.out', 'rb').read().decode()
        assert file_content == \
            "1489136209.000001: [10.10.10.1:40318 -> 10.10.10.2:8888]\n" + \
            http_request + "\n", "unexpected output"
        os.remove('test.out')

    # har2txt

    @pytest.mark.positive
    def test_har2txt_version(self):
        """Check version output"""

        command = ['har2txt', '-v']
        output = subprocess.check_output(
            command, stderr=subprocess.STDOUT
        ).decode()
        assert output == pcaper.__version__ + "\n", "unexpected output"

    @pytest.mark.positive
    def test_har2txt_input_file(
        self,
        prepare_har_file
    ):
        """Check har2txt parse input file correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        data = har_gen.generate_http_request_har_object(http_request)
        filename = prepare_har_file(data)
        command = ['har2txt', filename]
        output = subprocess.check_output(
            command, stderr=subprocess.STDOUT
        ).decode()
        assert output == \
            "1552079426.123000: [* -> 10.10.10.10]\n" + \
            http_request + "\n", "unexpected output"

    @pytest.mark.positive
    def test_har2txt_output_file(
        self,
        prepare_har_file
    ):
        """Check har2txt write result in output file correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        data = har_gen.generate_http_request_har_object(http_request)
        filename = prepare_har_file(data)
        command = ['har2txt', '-o', 'test.out', filename]
        output = subprocess.check_output(
            command, stderr=subprocess.STDOUT
        ).decode()
        assert output == "", "output is not empty"
        file_content = open('test.out', 'rb').read().decode()
        assert file_content == \
            "1552079426.123000: [* -> 10.10.10.10]\n" + \
            http_request + "\n", "unexpected output"
        os.remove('test.out')
