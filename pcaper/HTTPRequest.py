#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2018 Alexander Grechin
#
# Licensed under the BSD 3-Clause license.
# See LICENSE file in the project root for full license information.
#

""" Build HTTP request"""

from dpkt import http


class HTTPRequest(http.Request):
    """HTTP request class"""

    def __init__(self, request_dict=None):
        """Constructor"""

        self.version = ''
        self.uri = ''
        self.method = ''
        self.headers = {}
        self.origin_headers = {}
        self.body = ''
        self.timestamp = ''
        self.src = ''
        self.sport = ''
        self.dst = ''
        self.dport = ''
        self.origin = ''
        if request_dict:
            self.build(request_dict)

    def build(self, request_dict):
        """Convert HTTP request as dict to dpkt.http.Request object

        Args:
            request_dict (dict): HTTP request fields

        Returns:
            dpkt.http.Request: returns extended HTTP Request object
        """

        if 'version' in request_dict:
            self.version = request_dict["version"]
        if 'uri' in request_dict:
            self.uri = request_dict["uri"]
        if 'method' in request_dict:
            self.method = request_dict["method"]
        if 'headers' in request_dict:
            self.headers = request_dict["headers"]
        if 'origin_headers' in request_dict:
            self.origin_headers = request_dict["origin_headers"]
        if 'body' in request_dict:
            self.body = request_dict["body"]
        if 'timestamp' in request_dict:
            self.timestamp = request_dict['timestamp']
        if 'src' in request_dict:
            self.src = request_dict['src']
        if 'sport' in request_dict:
            self.sport = request_dict['sport']
        if 'dst' in request_dict:
            self.dst = request_dict['dst']
        if 'dport' in request_dict:
            self.dport = request_dict['dport']
        if 'origin' in request_dict:
            self.origin = request_dict['origin']
