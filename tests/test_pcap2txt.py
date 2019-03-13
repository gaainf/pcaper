#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2018 Alexander Grechin
#
# Licensed under the BSD 3-Clause license.
# See LICENSE file in the project root for full license information.
#

import dpkt
import mock
import os
import pytest
import tempfile
import pcaper
from pcaper import pcap2txt
import sys
import socket
from pcaper import pcap_gen


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

    # Tests

    @pytest.mark.positive
    def test_pcap2txt_version(self, capsys):
        """Check version output"""

        with pytest.raises(SystemExit) as system_exit:
            sys.argv.append('-v')
            pcap2txt.main()
            sys.argv.remove('-v')
        assert system_exit.value.code == 0
        captured = capsys.readouterr()
        # for python2 captured.err
        # for python3 captured.out
        assert captured.err == pcaper.__version__ + "\n" or \
            captured.out == pcaper.__version__ + "\n", "unexpected output"

    @pytest.mark.positive
    def test_pcap2txt_main(
        self,
        prepare_data_file,
        capsys
    ):
        """Check main function is worked out properly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        ethernet = pcap_gen.generate_custom_http_request_packet(http_request)
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_data_file(data)
        with mock.patch.object(
            pcap2txt.sys, 'argv',
            ['pcap2txt.py', filename]
        ):
            pcap2txt.main()
        captured = capsys.readouterr()
        # for python2 captured.err
        # for python3 captured.out
        assert captured.out == \
            "1489136209.000001: [10.10.10.1:40318 -> 10.10.10.2:8888]\n" + \
            http_request + "\n", "unexpected output"

    @pytest.mark.positive
    def test_pcap2txt_init(
        self,
        prepare_data_file
    ):
        """Check init function works correctly"""

        with mock.patch.object(pcap2txt, "main", return_value=42):
            with mock.patch.object(pcap2txt, "__name__", "__main__"):
                with mock.patch.object(pcap2txt.sys, 'exit') as mock_exit:
                    pcap2txt.init()
                    assert mock_exit.call_args[0][0] == 42

    @pytest.mark.positive
    def test_pcap2txt_input_file(
        self,
        prepare_data_file,
        capsys
    ):
        """Check main function parse input file correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        ethernet = pcap_gen.generate_custom_http_request_packet(http_request)
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_data_file(data)
        pcap2txt.pcap2txt({
            'input': filename,
            'output': False,
            'stats': False,
            'stats_only': False,
            'filter': None,
            'http_filter': None,
        })
        captured = capsys.readouterr()
        assert captured.out == \
            "1489136209.000001: [10.10.10.1:40318 -> 10.10.10.2:8888]\n" + \
            http_request + "\n", "unexpected output"

    @pytest.mark.positive
    def test_pcap2txt_filter(
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
        ethernet = pcap_gen.generate_custom_http_request_packet(
            http_request,
            params
        )
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_data_file(data)

        # match filter
        pcap2txt.pcap2txt({
            'input': filename,
            'output': False,
            'stats': False,
            'stats_only': False,
            'filter': 'ip.src == 10.4.0.136',
            'http_filter': None,
        })
        captured = capsys.readouterr()
        assert captured.out == \
            "1489136209.000001: [10.4.0.136:40318 -> 10.10.10.2:8888]\n" + \
            http_request + "\n", "unexpected output"

        # unmatch filter
        pcap2txt.pcap2txt({
            'input': filename,
            'output': False,
            'stats': False,
            'stats_only': False,
            'filter': 'ip.src == 10.4.1.136',
            'http_filter': None,
        })
        captured = capsys.readouterr()
        assert captured.out == "", "unexpected output"

    @pytest.mark.positive
    def test_pcap2txt_http_filter(
        self,
        prepare_data_file,
        capsys
    ):
        """Check main function parse input file
        with exclude-filter correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        params = {
            'ip': {
                'src': socket.inet_aton('10.4.0.136')
            }
        }
        ethernet = pcap_gen.generate_custom_http_request_packet(
            http_request,
            params
        )
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_data_file(data)

        # match filter
        pcap2txt.pcap2txt({
            'input': filename,
            'output': False,
            'stats': False,
            'stats_only': False,
            'filter': None,
            'http_filter': '"rambler" in http.uri',
        })
        captured = capsys.readouterr()
        assert captured.out == \
            "1489136209.000001: [10.4.0.136:40318 -> 10.10.10.2:8888]\n" + \
            http_request + "\n", "unexpected output"

        # unmatch filter
        pcap2txt.pcap2txt({
            'input': filename,
            'output': False,
            'stats': False,
            'stats_only': False,
            'filter': None,
            'http_filter': '"rambler" not in http.uri',
        })
        captured = capsys.readouterr()
        assert captured.out == "", "unexpected output"

    @pytest.mark.positive
    def test_parse_filter_and_http_filter(
        self,
        prepare_data_file,
        capsys
    ):
        """Check main function parse input file with excluding filter
        correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        params = {
            'ip': {
                'src': socket.inet_aton('10.4.0.136')
            }
        }
        ethernet = pcap_gen.generate_custom_http_request_packet(
            http_request,
            params
        )
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_data_file(data)

        # match filter
        pcap2txt.pcap2txt({
            'input': filename,
            'output': False,
            'stats': False,
            'stats_only': False,
            'filter': 'ip.src == 10.4.0.136',
            'http_filter': '"rambler" in http.uri',
        })
        captured = capsys.readouterr()
        assert captured.out == \
            "1489136209.000001: [10.4.0.136:40318 -> 10.10.10.2:8888]\n" + \
            http_request + "\n", "unexpected output"

        # unmatch filter
        pcap2txt.pcap2txt({
            'input': filename,
            'output': False,
            'stats': False,
            'stats_only': False,
            'filter': 'ip.src == 10.4.0.136',
            'http_filter': '"rambler" not in http.uri',
        })
        captured = capsys.readouterr()
        assert captured.out == "", "unexpected output"

    @pytest.mark.positive
    def test_pcap2txt_output_file(
        self,
        prepare_data_file,
        capsys
    ):
        """Check pcap2txt write result in output file correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        ethernet = pcap_gen.generate_custom_http_request_packet(http_request)
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_data_file(data)
        pcap2txt.pcap2txt({
            'input': filename,
            'output': 'test.out',
            'stats': False,
            'stats_only': False,
            'filter': None,
            'http_filter': None,
        })
        captured = capsys.readouterr()
        assert captured.out == "", "output is not empty"
        file_content = open('test.out', 'rb').read().decode("utf-8")
        assert file_content == \
            "1489136209.000001: [10.10.10.1:40318 -> 10.10.10.2:8888]\n" + \
            http_request + "\n", "unexpected output"
        os.remove('test.out')

    @pytest.mark.positive
    def test_pcap2txt_stats_only(
        self,
        prepare_data_file,
        capsys
    ):
        """Check stats-only flag handled correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        ethernet = pcap_gen.generate_custom_http_request_packet(http_request)
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_data_file(data)
        pcap2txt.pcap2txt({
            'input': filename,
            'output': False,
            'stats': False,
            'stats_only': True,
            'filter': None,
            'http_filter': None,
        })
        captured = capsys.readouterr()
        assert captured.out == \
            "Stats:\n\ttotal: 1\n\tcomplete: 1\n\t" + \
            "incorrect: 0\n\tincomplete: 0\n", "unexpected output"

    @pytest.mark.positive
    def test_pcap2txt_stats(
        self,
        prepare_data_file,
        capsys
    ):
        """Check stats flag handled correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        ethernet = pcap_gen.generate_custom_http_request_packet(http_request)
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_data_file(data)
        pcap2txt.pcap2txt({
            'input': filename,
            'output': False,
            'stats': True,
            'stats_only': False,
            'filter': None,
            'http_filter': None,
        })
        captured = capsys.readouterr()
        assert captured.out == \
            "1489136209.000001: [10.10.10.1:40318 -> 10.10.10.2:8888]\n" + \
            http_request + "\n" + \
            "Stats:\n\ttotal: 1\n\tcomplete: 1\n\t" + \
            "incorrect: 0\n\tincomplete: 0\n", "unexpected output"

    @pytest.mark.negative
    def test_pcap2txt_empty_input_file(
        self,
        capsys
    ):
        """Check empty input filename"""

        pcap2txt.pcap2txt({
            'input': None,
            'output': False,
            'stats': False,
            'stats_only': False,
            'http_filter': None
        })
        captured = capsys.readouterr()
        assert captured.err == \
            "Error: input filename is not specified or empty\n", \
            "unexpected output"
