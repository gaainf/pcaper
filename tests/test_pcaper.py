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
import json
from pcaper import pcap_gen
from pcaper import har_gen


class TestPcaper(object):

    # TextParser

    # Fixtures

    def set_text_file(self, filename, data):
        """Prepare text file"""

        with open(filename, "w") as file_handler:
            file_handler.write(data)
            file_handler.close()

    @pytest.fixture()
    def prepare_text_file(self):
        """Prepare text file decorator"""

        filename = {'file': ''}

        def _generate_temp_file(*args, **kwargs):
            filename['file'] = tempfile.NamedTemporaryFile(delete=False).name
            self.set_text_file(filename['file'], args[0])
            return filename['file']

        yield _generate_temp_file

        # remove file after test
        if os.path.isfile(filename['file']):
            os.remove(filename['file'])

    # Tests

    @pytest.mark.positive
    def test_read_text_parse_get_request_with_delimiter(
            self, prepare_text_file):
        """Check read_text method parses HTTP GET request correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\n" + \
                       "Host: rambler.ru\n" + \
                       "Content-Length: 0\n"
        data = http_request + "\n%--%\n"
        origin_http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                              "Host: rambler.ru\r\n" + \
                              "Content-Length: 0\r\n\r\n"

        filename = prepare_text_file(data)
        reader = pcaper.TextParser()

        packets = 0
        for request in reader.read_text({
            'input': filename
            }
        ):
            assert request['origin'] == origin_http_request, \
                "unexpected HTTP request data"
            packets = packets + 1
        assert packets == 1, "unexpected packets count"

    @pytest.mark.positive
    def test_read_text_parse_post_request_with_delimiter(
            self, prepare_text_file):
        """Check read_text method parses HTTP POST request correctly"""

        http_request = "POST https://rambler.ru/ HTTP/1.1\n" + \
                       "Host: rambler.ru\n" + \
                       "Content-Length: 2\n\n" +\
                       "{}"
        orig_http_request = "POST https://rambler.ru/ HTTP/1.1\r\n" + \
                            "Host: rambler.ru\r\n" + \
                            "Content-Length: 2\r\n\r\n" +\
                            "{}"
        data = http_request + "\n%--%\n"
        filename = prepare_text_file(data)
        reader = pcaper.TextParser()

        packets = 0
        for request in reader.read_text({
            'input': filename
            }
        ):
            assert request['origin'] == orig_http_request, \
                "unexpected HTTP request data"
            packets = packets + 1
        assert packets == 1, "unexpected packets count"

    @pytest.mark.positive
    def test_read_text_parse_single_get_request_without_delimiter(
            self, prepare_text_file):
        """Check read_text method parses HTTP GET request correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\n" + \
                       "Host: rambler.ru\n" + \
                       "Content-Length: 0\n"
        orig_http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                            "Host: rambler.ru\r\n" + \
                            "Content-Length: 0\r\n\r\n"
        data = http_request
        filename = prepare_text_file(data)
        reader = pcaper.TextParser()

        packets = 0
        for request in reader.read_text({
            'input': filename
            }
        ):
            assert request['origin'] == orig_http_request, \
                "unexpected HTTP request data"
            packets = packets + 1
        assert packets == 1, "unexpected packets count"

    @pytest.mark.positive
    def test_read_text_parse_original_newliner_handled_correctly(
            self, prepare_text_file):
        """Check read_text method parses \r\n correctly"""

        http_request = "POST / HTTP/1.1\r\n" +\
            "Host: rambler.ru\r\n" +\
            "Content-Length: 2\r\n" +\
            "Content-type: application/json\r\n" +\
            "x-header: 2.0\r\n\r\n" +\
            "{}"
        data = http_request + "\n%--%\n"
        filename = prepare_text_file(data)
        reader = pcaper.TextParser()
        parser = pcaper.HTTPParser()

        packets = 0
        for request in reader.read_text({
            'input': filename
            }
        ):
            assert request['origin'] == http_request, \
                "unexpected HTTP request data"
            assert parser.build_origin(request.to_dict()) == \
                http_request, \
                "unexpected HTTP request data"
            packets = packets + 1
        assert packets == 1, "unexpected packets count"

    @pytest.mark.negative
    def test_read_text_parse_incomplete_post_request(
            self, prepare_text_file):
        """Check read_text method parses incomplete request correctly"""

        http_request = "POST / HTTP/1.1\r\n" +\
            "Host: rambler.ru\r\n" +\
            "Content-Length: 3\r\n" +\
            "Content-type: application/json\r\n" +\
            "x-header: 2.0\r\n\r\n" +\
            "{}"
        data = http_request + "\n%--%\n"
        filename = prepare_text_file(data)
        reader = pcaper.TextParser()

        packets = 0
        for request in reader.read_text({
            'input': filename
            }
        ):
            packets = packets + 1
        assert packets == 0, "unexpected packets count"
        for request in reader.read_text({
            'input': filename,
            'fix_incomplete': True
            }
        ):
            packets = packets + 1
        assert packets == 1, "unexpected packets count"


    @pytest.mark.negative
    def test_read_text_parse_excess_body_request(
            self, prepare_text_file):
        """Check read_text method parses post request with excess body"""

        http_request = "POST / HTTP/1.1\n" +\
            "Host: rambler.ru\n" +\
            "Content-Length: 1\n" +\
            "Content-type: application/json\n" +\
            "x-header: 2.0\n\n" +\
            "{}"
        orig_http_request = "POST / HTTP/1.1\r\n" +\
            "Host: rambler.ru\r\n" +\
            "Content-Length: 1\r\n" +\
            "Content-type: application/json\r\n" +\
            "x-header: 2.0\r\n\r\n" +\
            "{"
        data = http_request + "\n%--%\n"
        filename = prepare_text_file(data)
        reader = pcaper.TextParser()

        packets = 0
        for request in reader.read_text({
            'input': filename
            }
        ):
            assert request['origin'] == orig_http_request, \
                "unexpected HTTP request data"
            packets = packets + 1
        assert packets == 1, "unexpected packets count"

    # PcapParser

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
        """Prepare pcap file decorator"""

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
    def test_http_parser_starts_with_http_method_is_true(self):
        """Check starts_with_http_method returns True
        if request starts with method"""

        parser = pcaper.HTTPParser()
        for method in dpkt.http.Request._Request__methods:
            http_request = (
                "%s https://rambler.ru/ HTTP/1.1\r\n" +
                "Host: rambler.ru\r\n" +
                "Content-Length: 0\r\n\r\n") % method
            assert parser.starts_with_http_method(http_request) is True, \
                "request should start with method"

    @pytest.mark.positive
    def test_http_parser_starts_with_http_method_is_false(self):
        """Check starts_with_http_method returns False
        if request starts with no method"""

        parser = pcaper.HTTPParser()
        assert parser.starts_with_http_method("some string") is False, \
            "function should return False if not request"

    @pytest.mark.positive
    def test_read_pcap_parse_http_get_request_with_content_length(
        self,
        prepare_pcap_file
    ):
        """Check read_pcap method parses HTTP GET request
        with content_length correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        ethernet = pcap_gen.generate_http_request_packet(http_request)
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_pcap_file(data)
        reader = pcaper.PcapParser()

        packets = 0
        for request in reader.read_pcap({
            'input': filename
            }
        ):
            assert request['origin'] == http_request, \
                "unexpected HTTP request data"
            packets = packets + 1
        assert packets == 1, "unexpected packets count"

    @pytest.mark.negative
    def test_read_pcap_parse_http_with_non_utf8_encoding(
        self,
        prepare_pcap_file
    ):
        """Check read_pcap method parses HTTP data
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
        ethernet = pcap_gen.generate_http_request_packet(http_request)
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_pcap_file(data)
        reader = pcaper.PcapParser()

        packets = 0
        for request in reader.read_pcap({
            'input': filename
            }
        ):
            assert request['origin'] == expected_http_request, \
                "unexpected HTTP request data"
            packets = packets + 1
        assert packets == 1, "unexpected packets count"

    @pytest.mark.positive
    def test_read_pcap_parse_http_get_request_without_content_length(
        self,
        prepare_pcap_file
    ):
        """Check read_pcap method parses HTTP GET request
        without content_length correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n\r\n"
        ethernet = pcap_gen.generate_http_request_packet(http_request)
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_pcap_file(data)
        reader = pcaper.PcapParser()

        packets = 0
        for request in reader.read_pcap({
            'input': filename
            }
        ):
            assert request['origin'] == http_request, \
                "unexpected HTTP request data"
            packets = packets + 1
        assert packets == 1, "unexpected packets count"

    @pytest.mark.negative
    def test_read_pcap_parse_empty_http_request(self, prepare_pcap_file):
        """Check read_pcap method parse empty HTTP request correctly"""

        http_request = ""
        ethernet = pcap_gen.generate_http_request_packet(http_request)
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_pcap_file(data)
        reader = pcaper.PcapParser()

        packets = 0
        for request in reader.read_pcap({
            'input': filename
            }
        ):
            assert request['origin'] == http_request, \
                "unexpected HTTP request data"
            packets = packets + 1
        assert packets == 0, "unexpected packets count"

    @pytest.mark.positive
    def test_read_pcap_parse_http_post_request(self, prepare_pcap_file):
        """Check read_pcap method parses HTTP post request correctly"""

        http_request = "POST https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n\r\n" + \
                       "param1=0\r\n"
        ethernet = pcap_gen.generate_http_request_packet(http_request)
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_pcap_file(data)
        reader = pcaper.PcapParser()

        packets = 0
        for request in reader.read_pcap({
            'input': filename
            }
        ):
            assert request['origin'] == http_request, \
                "unexpected HTTP request data"
            packets = packets + 1
        assert packets == 1, "unexpected packets count"

    @pytest.mark.positive
    def test_read_pcap_http_session(self, prepare_pcap_file):
        """Check read_pcap method reads http session"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        http_response = "HTTP/1.1 200 OK\r\n\r\n"
        data = pcap_gen.generate_tcp_session(http_request, http_response)
        filename = prepare_pcap_file(data)
        reader = pcaper.PcapParser()

        packets = 0
        for request in reader.read_pcap({
            'input': filename
            }
        ):
            assert request['origin'] == http_request, \
                "unexpected HTTP request data"
            packets = packets + 1
        assert packets == 1, "unexpected packets count"

    @pytest.mark.negative
    def test_read_pcap_only_http_response(self, prepare_pcap_file):
        """Check read_pcap method reads only HTTP requests"""

        http_response = "HTTP/1.1 200 OK\r\n\r\n"
        ethernet = pcap_gen.generate_http_response_packet(http_response)
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_pcap_file(data)
        reader = pcaper.PcapParser()

        packets = 0
        for request in reader.read_pcap({
            'input': filename
            }
        ):
            packets = packets + 1
        assert packets == 0, "unexpected packets count"

    @pytest.mark.positive
    def test_read_pcap_http_request_with_filter_by_dport(
        self,
        prepare_pcap_file
    ):
        """Check read_pcap method filters packets by tcp.dport correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        params = {
            'tcp': {
                'dport': 80
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
        filename = prepare_pcap_file(data)
        reader = pcaper.PcapParser()

        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'filter': 'tcp.dport == 80'
            }
        ):
            assert request['origin'] == http_request, \
                "unexpected HTTP request data"
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
    def test_read_pcap_http_request_with_excluding_filter_by_dport(
        self,
        prepare_pcap_file
    ):
        """Check read_pcap method excludes packets by tcp.dport correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        params = {
            'tcp': {
                'dport': 80
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
        filename = prepare_pcap_file(data)
        reader = pcaper.PcapParser()

        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'filter': 'tcp.dport != 80'
            }
        ):
            assert request['origin'] == http_request, \
                "unexpected HTTP request data"
            packets = packets + 1
        assert packets == 0, "unexpected packets count"

        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'filter': 'tcp.dport != 81'
            }
        ):
            packets = packets + 1
        assert packets == 1, "unexpected packets count"

    @pytest.mark.positive
    def test_read_pcap_http_request_with_filter_by_src(
        self,
        prepare_pcap_file
    ):
        """Check read_pcap method filters packets by ip.src correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        params = {
            'ip': {
                'src': socket.inet_aton('1.1.1.1')
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
        filename = prepare_pcap_file(data)
        reader = pcaper.PcapParser()

        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'filter': 'ip.src == 1.1.1.1'
            }
        ):
            assert request['origin'] == http_request, \
                "unexpected HTTP request data"
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
    def test_read_pcap_http_request_with_incorrect_ip_src_filter(
        self,
        prepare_pcap_file
    ):
        """Check read_pcap method with incorrect ip.src filter
        argument works correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        ethernet = pcap_gen.generate_custom_http_request_packet(
            http_request
        )
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_pcap_file(data)
        reader = pcaper.PcapParser()

        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'filter': 'ip.src == \"ff\"'
            }
        ):
            assert request['origin'] == http_request, \
                "unexpected HTTP request data"
            packets = packets + 1
        assert packets == 0, "unexpected packets count"

    @pytest.mark.positive
    def test_read_pcap_http_request_with_excluding_filter_by_src(
        self,
        prepare_pcap_file
    ):
        """Check read_pcap method excludes packets by ip.src correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        params = {
            'ip': {
                'src': socket.inet_aton('1.1.1.1')
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
        filename = prepare_pcap_file(data)
        reader = pcaper.PcapParser()

        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'filter': 'ip.src != 1.1.1.1'
            }
        ):
            assert request['origin'] == http_request, \
                "unexpected HTTP request data"
            packets = packets + 1
        assert packets == 0, "unexpected packets count"

        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'filter': 'ip.src != 1.1.1.2'
            }
        ):
            packets = packets + 1
        assert packets == 1, "unexpected packets count"

    @pytest.mark.positive
    def test_read_pcap_http_request_with_filter_and_http_filter_by_src(
        self,
        prepare_pcap_file
    ):
        """Check read_pcap method combines TCP/IP and HTTP packets filters
        correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        params1 = {
            'ip': {
                'src': socket.inet_aton('1.1.1.1')
            }
        }
        ethernet1 = pcap_gen.generate_custom_http_request_packet(
            http_request,
            params1
        )
        params2 = {
            'ip': {
                'src': socket.inet_aton('1.1.1.2')
            }
        }
        ethernet2 = pcap_gen.generate_custom_http_request_packet(
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
        filename = prepare_pcap_file(data)
        reader = pcaper.PcapParser()

        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'filter': 'ip.src == 1.1.1.1',
            'http_filter': '"rambler" in http.uri'
            }
        ):
            packets = packets + 1
            assert request['src'] == '1.1.1.1'
            assert "rambler" in request['uri']
        assert packets == 1, "unexpected packets count"

        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'filter': 'ip.src == 1.1.1.2',
            'http_filter': '"rambler" in http.uri'
            }
        ):
            packets = packets + 1
            assert request['src'] == '1.1.1.2'
            assert "rambler" in request['uri']
        assert packets == 1, "unexpected packets count"

        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'filter': 'ip.src == 1.1.1.1 or ip.src == 1.1.1.2',
            'http_filter': '"rambler" in http.uri'
            }
        ):
            packets = packets + 1
            assert "rambler" in request['uri']
        assert packets == 2, "unexpected packets count"

        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'filter': 'ip.src == 1.1.1.2',
            'http_filter': '"rambler" not in http.uri'
            }
        ):
            packets = packets + 1
        assert packets == 0, "unexpected packets count"

        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'filter': 'ip.src == 1.1.1.1',
            'http_filter': '"rambler" not in http.uri'
            }
        ):
            packets = packets + 1
        assert packets == 0, "unexpected packets count"

        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'filter': 'ip.src == 1.1.1.3',
            'http_filter': '"rambler" in http.uri'
            }
        ):
            packets = packets + 1
        assert packets == 0, "unexpected packets count"

        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'filter': 'ip.src == 1.1.1.1 or ip.src == 1.1.1.2',
            'http_filter': '"rambler" not in http.uri'
            }
        ):
            packets = packets + 1
        assert packets == 0, "unexpected packets count"

    @pytest.mark.positive
    def test_read_pcap_http_request_with_filter_by_dport_or_src(
        self,
        prepare_pcap_file
    ):
        """Check read_pcap method filters packets by tcp.dport
        or ip.src correctly"""

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
        ethernet1 = pcap_gen.generate_custom_http_request_packet(
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
        ethernet2 = pcap_gen.generate_custom_http_request_packet(
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
        filename = prepare_pcap_file(data)
        reader = pcaper.PcapParser()

        # tcp.dport == 80 or ip.src == 1.1.1.1
        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'filter': 'tcp.dport == 80 or ip.src == 1.1.1.1'
            }
        ):
            assert request['origin'] == http_request, \
                "unexpected HTTP request data"
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
                "unexpected HTTP request data"
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
        prepare_pcap_file
    ):
        """Check read_pcap method filters packets
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
        ethernet1 = pcap_gen.generate_custom_http_request_packet(
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
        ethernet2 = pcap_gen.generate_custom_http_request_packet(
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
        filename = prepare_pcap_file(data)
        reader = pcaper.PcapParser()

        # tcp.dport == 80 and ip.src == 1.1.1.2
        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'filter': 'tcp.dport == 80 and ip.src == 1.1.1.2'
            }
        ):
            assert request['origin'] == http_request, \
                "unexpected HTTP request data"
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
    def test_get_stats_check_stats(self, prepare_pcap_file):
        """Check get_stast method returns correct stats"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        ethernet = pcap_gen.generate_http_request_packet(http_request)
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_pcap_file(data)
        reader = pcaper.PcapParser()
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
        prepare_pcap_file
    ):
        """Check read_pcap method handle incomplete requests correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n"
        ethernet = pcap_gen.generate_http_request_packet(http_request)
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_pcap_file(data)
        reader = pcaper.PcapParser()

        packets = 0
        for request in reader.read_pcap({
            'input': filename
            }
        ):
            assert request['origin'] == http_request, \
                "unexpected HTTP request data"
            packets = packets + 1
        assert packets == 0, "unexpected packets count"
        reader_stats = reader.get_stats()
        assert reader_stats['total'] == 1, "unexpected total value"
        assert reader_stats['complete'] == 0, "unexpected total value"
        assert reader_stats['incorrect'] == 0, "unexpected total value"
        assert reader_stats['incomplete'] == 1, "unexpected total value"

    @pytest.mark.negative
    def test_read_pcap_http_request_incorrect_request(self, prepare_pcap_file):
        """Check read_pcap method handle incorrect requests correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        ethernet = pcap_gen.generate_http_request_packet(http_request)
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_pcap_file(data)
        reader = pcaper.PcapParser()

        packets = 0
        for request in reader.read_pcap({
            'input': filename
            }
        ):
            assert request['origin'] == http_request, \
                "unexpected HTTP request data"
            packets = packets + 1
        assert packets == 0, "unexpected packets count"
        reader_stats = reader.get_stats()
        assert reader_stats['total'] == 1, "unexpected total value"
        assert reader_stats['complete'] == 0, "unexpected total value"
        assert reader_stats['incorrect'] == 1, "unexpected total value"
        assert reader_stats['incomplete'] == 0, "unexpected total value"

    @pytest.mark.negative
    def test_read_pcap_empty_filter(self, prepare_pcap_file):
        """Check read_pcap method reads pcap with empty filter
        argument correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        ethernet = pcap_gen.generate_http_request_packet(http_request)
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_pcap_file(data)
        reader = pcaper.PcapParser()

        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'filter': ''
            }
        ):
            assert request['origin'] == http_request, \
                "unexpected HTTP request data"
            packets = packets + 1
        assert packets == 1, "unexpected packets count"

    @pytest.mark.negative
    def test_read_pcap_empty_http_filter(self, prepare_pcap_file):
        """Check read_pcap method reads pcap
        with empty http_filter argument correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        ethernet = pcap_gen.generate_http_request_packet(http_request)
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_pcap_file(data)
        reader = pcaper.PcapParser()

        packets = 0
        for request in reader.read_pcap({
            'input': filename,
            'http_filter': ''
            }
        ):
            assert request['origin'] == http_request, \
                "unexpected HTTP request data"
            packets = packets + 1
        assert packets == 1, "unexpected packets count"

    @pytest.mark.negative
    def test_read_pcap_parse_http_incorrect_post_request(
        self,
        prepare_pcap_file
    ):
        """Check read_pcap method parses incorrect http post request
         without exception"""

        http_request = "POST https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 12\r\n\r\n" + \
                       "param1=0\r\n"
        ethernet = pcap_gen.generate_http_request_packet(http_request)
        data = [{
            'timestamp': 1489136209.000001,
            'data': ethernet.__bytes__()
        }]
        filename = prepare_pcap_file(data)
        reader = pcaper.PcapParser()

        packets = 0
        for request in reader.read_pcap({
            'input': filename
            }
        ):
            assert request['origin'] == http_request, \
                "unexpected HTTP request data"
            packets = packets + 1
        assert packets == 0, "unexpected packets count"
        reader_stats = reader.get_stats()
        assert reader_stats['total'] == 1, "unexpected total value"
        assert reader_stats['complete'] == 0, "unexpected total value"
        assert reader_stats['incorrect'] == 1, "unexpected total value"
        assert reader_stats['incomplete'] == 0, "unexpected total value"

    @pytest.mark.negative
    def test_read_pcap_parse_pcapng_format(self, capsys, remove_data_file):
        """Check read_pcap method handles pcapng format exception"""

        reader = pcaper.PcapParser()

        packets = 0
        filename = remove_data_file()
        file_handler = open(filename, "wb")
        file_handler.write(pcap_gen.generate_pcapng_data())

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

    # HarParser

    # Fixtures

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

    @pytest.mark.positive
    def test_read_har_parse_get_request(self, prepare_har_file):
        """Check read_har method parses HTTP GET request correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        data = har_gen.generate_http_request_har_object(http_request)
        filename = prepare_har_file(data)
        reader = pcaper.HarParser()

        packets = 0
        for request in reader.read_har({
            'input': filename
            }
        ):
            assert request['origin'] == http_request, \
                "unexpected HTTP request data"
            packets = packets + 1
        assert packets == 1, "unexpected packets count"

    @pytest.mark.positive
    def test_read_har_parse_http_post_request(self, prepare_har_file):
        """Check read_har method parses HTTP post request correctly"""

        http_request = "POST https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 7\r\n\r\n" + \
                       "param=0"
        data = har_gen.generate_http_request_har_object(http_request)
        filename = prepare_har_file(data)
        reader = pcaper.HarParser()

        packets = 0
        for request in reader.read_har({
            'input': filename
            }
        ):
            assert request['origin'] == http_request, \
                "unexpected HTTP request data"
            packets = packets + 1
        assert packets == 1, "unexpected packets count"

    @pytest.mark.negative
    def test_read_har_parse_empty_protocol(self, prepare_har_file):
        """Check read_har method parses HTTP GET request
        without protocol correctly"""

        http_request = "GET https://rambler.ru/\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        data = har_gen.generate_http_request_har_object(http_request)
        filename = prepare_har_file(data)
        reader = pcaper.HarParser()

        packets = 0
        for request in reader.read_har({
            'input': filename
            }
        ):
            assert request['version'] == '0.9', \
                "unexpected HTTP request data"
            packets = packets + 1
        assert packets == 1, "unexpected packets count"

    @pytest.mark.negative
    def test_read_har_parse_absent_http_version(self, prepare_har_file):
        """Check read_har method handles incorrect json object correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        data = har_gen.generate_http_request_har_object(http_request)
        data['log']['entries'][-1]['request']['httpVersion'] = 'LALA'
        filename = prepare_har_file(data)
        reader = pcaper.HarParser()

        packets = 0
        for request in reader.read_har({
            'input': filename
            }
        ):
            assert request['version'] == '0.9', \
                "unexpected HTTP request data"
            packets = packets + 1
        assert packets == 1, "unexpected packets count"

        del data['log']['entries'][-1]['request']['httpVersion']
        filename = prepare_har_file(data)
        reader = pcaper.HarParser()

        packets = 0
        for request in reader.read_har({
            'input': filename
            }
        ):
            assert request['version'] == '0.9', \
                "unexpected HTTP request data"
            packets = packets + 1
        assert packets == 1, "unexpected packets count"

    @pytest.mark.negative
    def test_read_har_parse_absent_url(self, prepare_har_file):
        """Check read_har method handles incomplete json object correctly"""

        http_request = "GET https://rambler.ru/\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        data = har_gen.generate_http_request_har_object(http_request)
        del data['log']['entries'][-1]['request']['url']
        filename = prepare_har_file(data)
        reader = pcaper.HarParser()

        packets = 0
        for request in reader.read_har({
            'input': filename
            }
        ):
            packets = packets + 1
        assert packets == 0, "unexpected packets count"

    @pytest.mark.negative
    def test_read_har_parse_absent_method(self, prepare_har_file):
        """Check read_har method handles absent method as expected"""

        http_request = "GET https://rambler.ru/\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        data = har_gen.generate_http_request_har_object(http_request)
        del data['log']['entries'][-1]['request']['method']
        filename = prepare_har_file(data)
        reader = pcaper.HarParser()

        packets = 0
        for request in reader.read_har({
            'input': filename
            }
        ):
            packets = packets + 1
        assert packets == 0, "unexpected packets count"

    @pytest.mark.negative
    def test_read_har_parse_empty_json(self, prepare_har_file, capsys):
        """Check read_har method handles empty json as expected"""

        filename = prepare_har_file({})
        reader = pcaper.HarParser()

        # check exception text
        with pytest.raises(
                ValueError, match=r'incorrect har-file format'):
            packets = 0
            for request in reader.read_har({
                'input': filename
                }
            ):
                packets = packets + 1
        captured = capsys.readouterr()
        assert packets == 0, "unexpected packets count"
        assert captured.out.startswith("")

    @pytest.mark.positive
    def test_read_har_parse_incorrect_json(self, prepare_har_file):
        """Check read_har method handles incorrect json as expected"""

        filename = prepare_har_file({"log": {"entries": ['REQ']}})
        reader = pcaper.HarParser()

        packets = 0
        for request in reader.read_har({
            'input': filename
            }
        ):
            packets = packets + 1
        assert packets == 0, "unexpected packets count"

    @pytest.mark.negative
    def test_read_har_empty_input_parameter(self, prepare_har_file, capsys):
        """Check read_har method raises exception
        on empty input file parameter"""

        reader = pcaper.HarParser()

        # check exception text
        with pytest.raises(
                ValueError, match=r'input filename is not specified or empty'):
            packets = 0
            for request in reader.read_har({}):
                packets = packets + 1
        captured = capsys.readouterr()
        assert packets == 0, "unexpected packets count"
        assert captured.out.startswith("")

    @pytest.mark.negative
    def test_read_har_empty_http_filter(self, prepare_har_file):
        """Check read_har method reads har
        with empty http_filter argument correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        data = har_gen.generate_http_request_har_object(http_request)
        filename = prepare_har_file(data)
        reader = pcaper.HarParser()

        packets = 0
        for request in reader.read_har({
            'input': filename,
            'http_filter': ''
            }
        ):
            assert request['origin'] == http_request, \
                "unexpected HTTP request data"
            packets = packets + 1
        assert packets == 1, "unexpected packets count"

    @pytest.mark.negative
    def test_read_har_parse_unexpected_post_data(self, prepare_har_file):
        """Check read_har method handles unexpected postData
        format correctly"""

        http_request = "POST https://rambler.ru/\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 7\r\n\r\n" + \
                       "param=0"
        data = har_gen.generate_http_request_har_object(http_request)
        del data['log']['entries'][-1]['request']['postData']['text']
        filename = prepare_har_file(data)
        reader = pcaper.HarParser()

        packets = 0
        for request in reader.read_har({
            'input': filename
            }
        ):
            packets = packets + 1
        assert packets == 0, "unexpected packets count"

    @pytest.mark.positive
    def test_read_har_parse_another_timestamp_format(
        self,
        prepare_har_file
    ):
        """Check read_har method handles another timestamp
        format correctly"""

        http_request = "POST https://rambler.ru/\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 7\r\n\r\n" + \
                       "param=0"
        data = har_gen.generate_http_request_har_object(http_request)
        data['log']['entries'][-1]['startedDateTime'] = \
            '2018-11-15T19:14:11.930+03:00'
        filename = prepare_har_file(data)
        reader = pcaper.HarParser()

        packets = 0
        for request in reader.read_har({
            'input': filename
            }
        ):
            packets = packets + 1
        assert packets == 1, "unexpected packets count"

    @pytest.mark.negative
    def test_read_har_parse_unexpected_timestamp_format(
        self,
        prepare_har_file
    ):
        """Check read_har method handles unexpected timestamp
        format correctly"""

        http_request = "POST https://rambler.ru/\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 7\r\n\r\n" + \
                       "param=0"
        data = har_gen.generate_http_request_har_object(http_request)
        data['log']['entries'][-1]['startedDateTime'] = \
            '2018-11-15T19:14'
        filename = prepare_har_file(data)
        reader = pcaper.HarParser()

        packets = 0
        for request in reader.read_har({
            'input': filename
            }
        ):
            packets = packets + 1
        assert packets == 1, "unexpected packets count"

    # HTTPParser

    @pytest.mark.negative
    def test_parse_request_no_method(self):
        """Check HTTPParser parse_request method handles HTTP GET request
        without HTTP method and protocol corectly"""

        http_request = "https://rambler.ru/\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        parser = pcaper.HTTPParser()

        parsed_request = parser.parse_request(http_request)
        assert parsed_request is None, "unexpected result"

    @pytest.mark.negative
    def test_parse_request_bad_method(self):
        """Check HTTPParser parse_request method handles HTTP GET request
        with incorrect base line corectly"""

        http_request = "FORGET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        parser = pcaper.HTTPParser()

        parsed_request = parser.parse_request(http_request)
        assert parsed_request is None, "unexpected result"

    @pytest.mark.negative
    def test_parse_request_no_protocol(self):
        """Check HTTPParser parse_request method handles HTTP GET request
        without HTTP protocol corectly"""

        http_request = "GET https://rambler.ru/\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        parser = pcaper.HTTPParser()

        parsed_request = parser.parse_request(http_request)
        assert parsed_request['version'] == '0.9', "unexpected result"

    @pytest.mark.negative
    def test_parse_request_bad_protocol(self):
        """Check HTTPParser parse_request method handles HTTP GET request
        with bad HTTP protocol corectly"""

        http_request = "GET https://rambler.ru/ HTTPS/1.0\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        parser = pcaper.HTTPParser()

        parsed_request = parser.parse_request(http_request)
        assert parsed_request is None, "unexpected result"

    @pytest.mark.negative
    def test_parse_request_bad_headers(self):
        """Check HTTPParser parse_request method handles HTTP GET request
        with bad HTTP headers corectly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "H ost: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        parser = pcaper.HTTPParser()

        parsed_request = parser.parse_request(http_request)
        assert len(parsed_request['headers']) == 0, "unexpected result"


    @pytest.mark.negative
    def test_parse_request_unicode_header(self):
        """Check HTTPParser parse_request method handles HTTP GET request
        with unicode in HTTP header corectly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "User-Agent: Mozilla/5.0 (Windows NT 6.1; " + \
                       "Trident/7.0; ОД; rv:11.0) like Gecko\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        parser = pcaper.HTTPParser()

        parsed_request = parser.parse_request(http_request)
        assert len(parsed_request['headers']) == 2, "unexpected result"


    @pytest.mark.positive
    def test_build_origin_post_request(self):
        """Check HTTPParser build_origin method handles HTTP POST request
        corectly"""

        http_request = "POST https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 7\r\n\r\n" + \
                       "param=1"
        parser = pcaper.HTTPParser()

        parsed_request = parser.parse_request(http_request)
        builded_request = parser.build_origin(parsed_request)
        assert builded_request == http_request, "unexpected result"
