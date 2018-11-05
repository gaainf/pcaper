#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2018 Alexander Grechin
#
# Licensed under the BSD 3-Clause license.
# See LICENSE file in the project root for full license information.
#

import argparse
from pcaper import HTTPRequest
from . import _version
import sys


def parse_args():
    parser = argparse.ArgumentParser(
        add_help=True
    )
    parser.add_argument('input', help='input filename')
    parser.add_argument('-o', '--output', help='output filename')
    parser.add_argument('-f', '--filter', help='pcap filter')
    parser.add_argument(
        '-s', '--stats', help='print stats', action='store_true'
    )
    parser.add_argument(
        '-S', '--stats-only', help='print stats only', action='store_true'
    )
    parser.add_argument(
        '-v', '--version', help='print version', action='version',
        version='{version}'.format(version=_version.__version__)
    )

    return vars(parser.parse_args())


def parse_http(args):
    reader = HTTPRequest()

    if args['output']:
        file_handler = open(args['output'], "w")
    else:
        file_handler = sys.stdout
    if args['stats_only']:
        for request in reader.read_pcap(args):
            pass
    else:
        for request in reader.read_pcap(args):
            file_handler.write("%0.6f: [%s:%d -> %s:%d]\n%s\n" % (
                request['timestamp'],
                request['src'],
                request['sport'],
                request['dst'],
                request['dport'],
                request['origin']
            ))
    if file_handler is not sys.stdout:
        file_handler.close()

    if args['stats'] or args['stats_only']:
        print("Stats:")
        stats = reader.get_stats()
        for key in stats.keys():
            print("\t%s: %d" % (key, stats[key]))


def main():
    """The main function"""

    args = parse_args()
    parse_http(args)


if __name__ == '__main__':
    main()
