#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2018 Alexander Grechin
#
# Licensed under the BSD 3-Clause license.
# See LICENSE file in the project root for full license information.
#
# Additional methods for har file generating

import pcaper
from datetime import datetime


def format_microseconds(date, accuracy=3):
    """Format datetime in microseconds
    Args:
        date (datetime): date
        accuracy (int): round accuaracy

    Returns:
        datetime: formated string
    """

    return datetime.strftime(date, '%Y-%m-%dT%H:%M:%S.') + \
        datetime.strftime(date, '%f')[:accuracy] + 'Z'


def get_har_file_struct():
    """Generate har file structure

    Returns:
        dict: har file structure
    """

    har_structure = {
        "log": {
            "version": "1.2",
            "creator": {
                "name": "WebInspector",
                "version": "537.36"
            },
            "pages": [
                {
                    "startedDateTime": format_microseconds(
                        datetime.strptime(
                            '2019-03-08T21:10:26.123Z',
                            '%Y-%m-%dT%H:%M:%S.%fZ'
                        )
                    ),
                    "id": "page_1",
                    "title": "http://example.com/",
                    "pageTimings": {
                        "onContentLoad": 0.0,
                        "onLoad": 0.0
                    }
                }
            ],
            "entries": []
        }
    }

    return har_structure


def generate_http_request_har_object(http_request):
    """Generate HTTP request as har object

    Args:
        http_request (dict): HTTP request

    Returns:
        str: HTTP request string in har format
    """

    har_structure = get_har_file_struct()
    parser = pcaper.HTTPParser()
    request_dict = parser.parse_request(http_request)

    har_structure["log"]["entries"].append({
        "startedDateTime": format_microseconds(
            datetime.strptime(
                '2019-03-08T21:10:26.123Z',
                '%Y-%m-%dT%H:%M:%S.%fZ'
            )
        ),
        "time": 0.0,
        "request": {
            "method": request_dict["method"],
            "url": request_dict["uri"],
            "httpVersion": "HTTP/" + request_dict["version"],
            "headers": [
                {"name": k, "value": v}
                for k, v in request_dict["origin_headers"].items()
            ],
            "queryString": [],
            "cookies": [],
            "headersSize": 0,
            "bodySize": 0,
            "postData"
            if 'body' in request_dict and request_dict['body']
            else None: {
                "mimeType": "text/plain;charset=UTF-8",
                "text": request_dict['body']
            } if 'body' in request_dict and request_dict['body']
            else None
        },
        "response": {
            "status": 200,
            "statusText": "",
            "httpVersion": "",
            "headers": [],
            "cookies": [],
            "content": {
                "size": 0,
                "mimeType": "x-unknown",
                "compression": 0
            },
            "redirectURL": "",
            "headersSize": 0,
            "bodySize": 0,
            "_transferSize": 00
        },
        "cache": {},
        "timings": {
            "blocked": 0.0,
            "dns": 0.0,
            "ssl": -1,
            "connect": 0.0,
            "send": 0.0,
            "wait": 0.0,
            "receive": 0.0,
            "_blocked_queueing": 0.0
        },
        "serverIPAddress": "10.10.10.10",
        "_initiator": {
            "type": "other"
        },
        "_priority": "VeryHigh",
        "_resourceType": "other",
        "connection": "0",
        "pageref": "page_1"
    })

    return har_structure
