#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2018 Alexander Grechin
#
# Licensed under the BSD 3-Clause license.
# See LICENSE file in the project root for full license information.
#

import mock
import os
import pytest
import tempfile
import pcaper
from pcaper import har2txt
import sys
import json
from pcaper import har_gen


class TestParseHttp(object):

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
    def test_har2txt_version(self, capsys):
        """Check version output"""

        with pytest.raises(SystemExit) as system_exit:
            sys.argv.append('-v')
            har2txt.main()
            sys.argv.remove('-v')
        assert system_exit.value.code == 0
        captured = capsys.readouterr()
        # for python2 captured.err
        # for python3 captured.out
        assert captured.err == pcaper.__version__ + "\n" or \
            captured.out == pcaper.__version__ + "\n", "unexpected output"

    @pytest.mark.positive
    def test_har2txt_main(
        self,
        prepare_har_file,
        capsys
    ):
        """Check main function is worked out properly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        data = har_gen.generate_http_request_har_object(http_request)
        filename = prepare_har_file(data)
        with mock.patch.object(
            har2txt.sys, 'argv',
            ['har2txt.py', filename]
        ):
            har2txt.main()
        captured = capsys.readouterr()
        # for python2 captured.err
        # for python3 captured.out
        assert captured.out == \
            "1552079426.123000: [* -> 10.10.10.10]\n" + \
            http_request + "\n", "unexpected output"

    @pytest.mark.positive
    def test_har2txt_init(
        self,
        prepare_har_file
    ):
        """Check init function works correctly"""

        with mock.patch.object(har2txt, "main", return_value=42):
            with mock.patch.object(har2txt, "__name__", "__main__"):
                with mock.patch.object(har2txt.sys, 'exit') as mock_exit:
                    har2txt.init()
                    assert mock_exit.call_args[0][0] == 42

    @pytest.mark.positive
    def test_har2txt_input_file(
        self,
        prepare_har_file,
        capsys
    ):
        """Check main function parse input file correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        data = har_gen.generate_http_request_har_object(http_request)
        filename = prepare_har_file(data)
        har2txt.har2txt({
            'input': filename,
            'output': False,
            'stats': False,
            'stats_only': False,
            'http_filter': None,
        })
        captured = capsys.readouterr()
        assert captured.out == \
            "1552079426.123000: [* -> 10.10.10.10]\n" + \
            http_request + "\n", "unexpected output"

    @pytest.mark.positive
    def test_har2txt_http_filter(
        self,
        prepare_har_file,
        capsys
    ):
        """Check main function parse input file
        with exclude-filter correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        data = har_gen.generate_http_request_har_object(http_request)
        filename = prepare_har_file(data)

        # match filter
        har2txt.har2txt({
            'input': filename,
            'output': False,
            'stats': False,
            'stats_only': False,
            'http_filter': '"rambler" in http.uri',
        })
        captured = capsys.readouterr()
        assert captured.out == \
            "1552079426.123000: [* -> 10.10.10.10]\n" + \
            http_request + "\n", "unexpected output"

        # unmatch filter
        har2txt.har2txt({
            'input': filename,
            'output': False,
            'stats': False,
            'stats_only': False,
            'http_filter': '"rambler" not in http.uri',
        })
        captured = capsys.readouterr()
        assert captured.out == "", "unexpected output"

    @pytest.mark.positive
    def test_har2txt_output_file(
        self,
        prepare_har_file,
        capsys
    ):
        """Check har2txt write result in output file correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        data = har_gen.generate_http_request_har_object(http_request)
        filename = prepare_har_file(data)

        har2txt.har2txt({
            'input': filename,
            'output': 'test.out',
            'stats': False,
            'stats_only': False,
            'http_filter': None
        })
        captured = capsys.readouterr()
        assert captured.out == "", "output is not empty"
        file_content = open('test.out', 'rb').read().decode("utf-8")
        assert file_content == \
            "1552079426.123000: [* -> 10.10.10.10]\n" + \
            http_request + "\n", "unexpected output"
        os.remove('test.out')

    @pytest.mark.positive
    def test_har2txt_stats_only(
        self,
        prepare_har_file,
        capsys
    ):
        """Check stats-only flag handled correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        data = har_gen.generate_http_request_har_object(http_request)
        filename = prepare_har_file(data)

        har2txt.har2txt({
            'input': filename,
            'output': False,
            'stats': False,
            'stats_only': True,
            'http_filter': None
        })
        captured = capsys.readouterr()
        assert captured.out == \
            "Stats:\n\ttotal: 1\n\tcomplete: 1\n\t" + \
            "incorrect: 0\n\tincomplete: 0\n", "unexpected output"

    @pytest.mark.positive
    def test_har2txt_stats(
        self,
        prepare_har_file,
        capsys
    ):
        """Check stats flag handled correctly"""

        http_request = "GET https://rambler.ru/ HTTP/1.1\r\n" + \
                       "Host: rambler.ru\r\n" + \
                       "Content-Length: 0\r\n\r\n"
        data = har_gen.generate_http_request_har_object(http_request)
        filename = prepare_har_file(data)

        har2txt.har2txt({
            'input': filename,
            'output': False,
            'stats': True,
            'stats_only': False,
            'http_filter': None
        })
        captured = capsys.readouterr()
        assert captured.out == \
            "1552079426.123000: [* -> 10.10.10.10]\n" + \
            http_request + "\n" + \
            "Stats:\n\ttotal: 1\n\tcomplete: 1\n\t" + \
            "incorrect: 0\n\tincomplete: 0\n", "unexpected output"

    @pytest.mark.negative
    def test_har2txt_empty_input_file(
        self,
        capsys
    ):
        """Check empty input filename"""

        har2txt.har2txt({
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
