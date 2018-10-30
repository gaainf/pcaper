#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2018 Alexander Grechin
#
# Licensed under the BSD 3-Clause license.
# See LICENSE file in the project root for full license information.
#

"""Parser of pcap file"""

import argparse
import pcaper


def main():
    """The main function"""

    parser = argparse.ArgumentParser(
        prog=__file__,
        usage='%(prog)s [options]',
        add_help=True
    )
    parser.add_argument('-i', '--input', help='Input filename', required=True)
    parser.add_argument('-o', '--output', help='Output filename')
    parser.add_argument('-f', '--filter', help='Pcap filter')

    args = parser.parse_args()

    reader = pcaper.HTTPRequest()
    for request in reader.read_pcap(vars(args)):
        print("%0.6f: [%s:%d -> %s:%d]\n%s") % (
            request['timestamp'],
            request['src'],
            request['sport'],
            request['dst'],
            request['dport'],
            request['original']
        )

    print "Stats:"
    stats = reader.get_stats()
    for key in stats.keys():
        print "\t%s: %d" % (key, stats[key])


if __name__ == '__main__':
    main()
