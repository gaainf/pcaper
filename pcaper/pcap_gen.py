#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2018 Alexander Grechin
#
# Licensed under the BSD 3-Clause license.
# See LICENSE file in the project root for full license information.
#
# Additional methods for pcap file generating

import dpkt


def generate_syn_packet():
    """Generate SYN packet of TCP session

    Returns:
        dpkt.Ethernet: SYN packet
    """

    tcp = dpkt.tcp.TCP(
        b'\x9d\x7e\x22\xb8\xb6\xce\xe8\x3c\x00\x00\x00\x00' +
        b'\xa0\x02\x72\x10\x3c\xf8\x00\x00\x02\x04\x05\xb4' +
        b'\x04\x02\x08\x0a\x3c\x58\x15\xa3\x00\x00\x00\x00' +
        b'\x01\x03\x03\x03'
    )
    ip = dpkt.ip.IP(
        b'\x45\x00\x00\x3c\xfd\x9f\x40\x00\x40\x06\x00\x53' +
        b'\x0a\x0a\x0a\x01' +  # src
        b'\x0a\x0a\x0a\x02'    # dst
    )
    ip.data = tcp
    ethernet = dpkt.ethernet.Ethernet(
        b'\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x01\x08\x00'
    )
    ethernet.data = ip
    return ethernet


def generate_synack_packet():
    """Generate SYN-ACK packet of TCP session

    Returns:
        dpkt.Ethernet: SYN-ACK packet
    """

    tcp = dpkt.tcp.TCP(
        b'\x22\xb8\x9d\x7e\xb7\x1a\x15\x3f\xb6\xce\xe8\x3d' +
        b'\xa0\x12\x71\x20\xe4\xa9\x00\x00\x02\x04\x05\xb4' +
        b'\x04\x02\x08\x0a\x90\xfd\xa6\xc4\x3c\x58\x15\xa3' +
        b'\x01\x03\x03\x09'
    )
    ip = dpkt.ip.IP(
        b'\x45\x00\x00\x3c\x00\x00\x40\x00\x3e\x06\xff\xf2' +
        b'\x0a\x0a\x0a\x02' +
        b'\x0a\x0a\x0a\x01'
    )
    ip.data = tcp
    ethernet = dpkt.ethernet.Ethernet(
        b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x02\x08\x00'
    )
    ethernet.data = ip
    return ethernet


def generate_ack_packet():
    """Generate empty ACK packet before HTTP request

    Returns:
        dpkt.Ethernet: ACK packet
    """

    tcp = dpkt.tcp.TCP(
        b'\x9d\x7e\x22\xb8\xb6\xce\xe8\x3d\xb7\x1a\x15\x40' +
        b'\x80\x10\x0e\x42\x3c\xf0\x00\x00\x01\x01\x08\x0a' +
        b'\x3c\x58\x15\xa4\x90\xfd\xa6\xc4'
    )
    ip = dpkt.ip.IP(
        b'\x45\x00\x00\x34\xfd\xa0\x40\x00\x40\x06\x00\x5a' +
        b'\x0a\x0a\x0a\x01' +
        b'\x0a\x0a\x0a\x02'
    )
    ip.data = tcp
    ethernet = dpkt.ethernet.Ethernet(
        b'\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x01\x08\x00'
    )
    ethernet.data = ip
    return ethernet


def generate_http_request_packet(data):
    """Generate HTTP request packet with specified payload

    Args:
        data: binnary TCP payload data

    Returns:
        dpkt.Ethernet: HTTP request packet
    """

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


def generate_ack_after_request_packet():
    """Generate empty ACK packet after request

    Returns:
        dpkt.Ethernet: ACK packet
    """

    tcp = dpkt.tcp.TCP(
        b'\x22\xb8\x9d\x7e\xb7\x1a\x15\x40\xb6\xce\xe8\x86' +
        b'\x80\x10\x00\x3d\x80\x6a\x00\x00\x01\x01\x08\x0a' +
        b'\x90\xfd\xa6\xc4\x3c\x58\x15\xa4'
    )
    ip = dpkt.ip.IP(
        b'\x45\x00\x00\x34\xb3\x84\x40\x00\x3e\x06\x4c\x76' +
        b'\x0a\x0a\x0a\x02' +
        b'\x0a\x0a\x0a\x01'
    )
    ip.data = tcp
    ethernet = dpkt.ethernet.Ethernet(
        b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x02\x08\x00'
    )
    ethernet.data = ip
    return ethernet


def generate_http_response_packet(data):
    """Generate HTTP response packet

    Returns:
        dpkt.Ethernet: HTTP response packet
    """

    tcp = dpkt.tcp.TCP(
        b'\x22\xb8\x9d\x7e\xb7\x1a\x15\x40\xb6\xce\xe8\x86' +
        b'\x80\x18\x00\x3d\x46\xbf\x00\x00\x01\x01\x08\x0a' +
        b'\x90\xfd\xa6\xcf\x3c\x58\x15\xa4'
    )
    tcp.data = data.encode("utf-8")
    ip = dpkt.ip.IP(
        b'\x45\x00\x0a\x03\xb3\x85\x40\x00\x3e\x06\x42\xa6' +
        b'\x0a\x0a\x0a\x02' +
        b'\x0a\x0a\x0a\x01'
    )
    ip.len = len(data)
    ip.data = tcp
    ethernet = dpkt.ethernet.Ethernet(
        b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x02\x08\x00'
    )
    ethernet.data = ip
    return ethernet


def generate_ack_after_response_packet():
    """Generate empty ACK packet after HTTP response

    Returns:
        dpkt.Ethernet: ACK packet
    """

    tcp = dpkt.tcp.TCP(
        b'\x9d\x7e\x22\xb8\xb6\xce\xe8\x86\xb7\x1a\x15\x53' +
        b'\x80\x10\x54\xa0\x3c\xf0\x00\x00\x01\x01\x08\x0a' +
        b'\x3c\x58\x15\xd2\x90\xfd\xa6\xd2'
    )
    ip = dpkt.ip.IP(
        b'\x45\x00\x00\x34\xfd\xe9\x40\x00\x40\x06\x00\x11' +
        b'\x0a\x0a\x0a\x01' +
        b'\x0a\x0a\x0a\x02'
    )
    ip.data = tcp
    ethernet = dpkt.ethernet.Ethernet(
        b'\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x01\x08\x00'
    )
    ethernet.data = ip
    return ethernet


def generate_first_fin_packet():
    """Generate the first FIN packet

    Returns:
        dpkt.Ethernet: FIN packet
    """

    tcp = dpkt.tcp.TCP(
        b'\x9d\x7e\x22\xb8\xb6\xce\xe8\x86\xb7\x1a\x15\x53' +
        b'\x80\x11\x54\xa0\x3c\xf0\x00\x00\x01\x01\x08\x0a' +
        b'\x3c\x58\x15\xd2\x90\xfd\xa6\xd2'
    )
    ip = dpkt.ip.IP(
        b'\x45\x00\x00\x34\xfd\xea\x40\x00\x40\x06\x00\x10' +
        b'\x0a\x0a\x0a\x01' +
        b'\x0a\x0a\x0a\x02'
    )
    ip.data = tcp
    ethernet = dpkt.ethernet.Ethernet(
        b'\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x01\x08\x00'
    )
    ethernet.data = ip
    return ethernet


def generate_second_fin_packet():
    """Generate the second FIN packet

    Returns:
        dpkt.Ethernet: FIN packet
    """

    tcp = dpkt.tcp.TCP(
        b'\x22\xb8\x9d\x7e\xb7\x1a\x15\x53\xb6\xce\xe8\x87' +
        b'\x80\x11\x00\x3d\x53\x05\x00\x00\x01\x01\x08\x0a' +
        b'\x90\xfd\xa6\xd2\x3c\x58\x15\xd2'
    )
    ip = dpkt.ip.IP(
        b'\x45\x00\x00\x34\xb4\x46\x40\x00\x3e\x06\x4b\xb4' +
        b'\x0a\x0a\x0a\x01' +
        b'\x0a\x0a\x0a\x02'
    )
    ip.data = tcp
    ethernet = dpkt.ethernet.Ethernet(
        b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x02\x08\x00'
    )
    ethernet.data = ip
    return ethernet


def generate_ack_after_second_fin_packet():
    """Generate ACK packet after second FIN

    Returns:
        dpkt.Ethernet: ACK packet
    """

    tcp = dpkt.tcp.TCP(
        b'\x9d\x7e\x22\xb8\xb6\xce\xe8\x87\x7e\xb7\x1a\x16' +
        b'\x80\x10\x54\xa0\x3c\xf0\x00\x00\x01\x01\x08\x0a' +
        b'\x3c\x58\x15\xd4\x90\xfd\xa6\xd2'
    )
    ip = dpkt.ip.IP(
        b'\x45\x00\x00\x34\xfd\xeb\x40\x00\x40\x06\x00\x0f' +
        b'\x0a\x0a\x0a\x02' +
        b'\x0a\x0a\x0a\x01'
    )
    ip.data = tcp
    ethernet = dpkt.ethernet.Ethernet(
        b'\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x01\x08\x00'
    )
    ethernet.data = ip
    return ethernet


def generate_tcp_session(http_request, http_response):
    """Generate full request-response TCP session

    Args:
        http_request (dpkt.http.Request): HTTP request
        http_response (dpkt.http.Response): Http response

    Returns:
        str: binnary data in pcap format
    """

    data = [
        {
            'timestamp': 1489136209.000001,
            'data': generate_syn_packet().__bytes__()
        },
        {
            'timestamp': 1489136209.000002,
            'data': generate_synack_packet().__bytes__()
        },
        {
            'timestamp': 1489136209.000003,
            'data': generate_ack_packet().__bytes__()
        },
        {
            'timestamp': 1489136209.000004,
            'data': generate_http_request_packet(
                http_request
            ).__bytes__()
        },
        {
            'timestamp': 1489136209.000005,
            'data': generate_ack_after_request_packet().__bytes__()
        },
        {
            'timestamp': 1489136209.000006,
            'data': generate_http_response_packet(
                http_response
            ).__bytes__()
        },
        {
            'timestamp': 1489136209.000007,
            'data': generate_ack_after_response_packet().__bytes__()
        },
        {
            'timestamp': 1489136209.000008,
            'data': generate_first_fin_packet().__bytes__()
        },
        {
            'timestamp': 1489136209.000009,
            'data': generate_second_fin_packet().__bytes__()
        },
        {
            'timestamp': 1489136209.000010,
            'data': generate_ack_after_second_fin_packet().__bytes__()
        },
    ]
    return data


def replace_params(ethernet, params=[]):
    """Replace parameters of Ethernet, TCP and/or IP packet

    Args:
        ethernet (str): Ethernet packet
        params (dict): packet parameters

    Returns:
        dpkt.Ethernet: Ethernet packet including IP and TCP data
    """

    if 'tcp' in params:
        for field in params['tcp']:
            setattr(ethernet.data.data, field, params['tcp'][field])
    if 'ip' in params:
        for field in params['ip']:
            setattr(ethernet.data, field, params['ip'][field])
    if 'ethernet' in params:
        for field in params['ethernet']:
            setattr(ethernet, field, params['ethernet'][field])


def generate_custom_http_request_packet(data, params=[]):
    """Generate custom HTTP request packet with specified payload

    Args:
        data (str): binnary TCP payload data
        params (dict): packet parameters

    Returns:
        dpkt.Ethernet: HTTP request packet
    """

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
    replace_params(ethernet, params)
    return ethernet


def generate_pcapng_data():
    """Generate data in pcapng format

    Returns:
        str: binnary data in pcapng format
    """

    data = \
        b'\x0a\x0d\x0d\x0a\x88\x00\x00\x00\x4d\x3c\x2b\x1a\x01\x00\x00' + \
        b'\x00\xff\xff\xff\xff\xff\xff\xff\xff\x03\x00\x2d\x00\x4d\x61' + \
        b'\x63\x20\x4f\x53\x20\x58\x20\x31\x30\x2e\x31\x33\x2e\x33\x2c' + \
        b'\x20\x62\x75\x69\x6c\x64\x20\x31\x37\x44\x34\x37\x20\x28\x44' + \
        b'\x61\x72\x77\x69\x6e\x20\x31\x37\x2e\x34\x2e\x30\x29\x00\x00' + \
        b'\x00\x04\x00\x2d\x00\x44\x75\x6d\x70\x63\x61\x70\x20\x28\x57' + \
        b'\x69\x72\x65\x73\x68\x61\x72\x6b\x29\x20\x32\x2e\x32\x2e\x32' + \
        b'\x20\x28\x76\x32\x2e\x32\x2e\x32\x2d\x30\x2d\x67\x37\x37\x35' + \
        b'\x66\x62\x30\x38\x29\x00\x00\x00\x00\x00\x00\x00\x88\x00\x00' + \
        b'\x00\x01\x00\x00\x00\x5c\x00\x00\x00\x01\x00\x00\x00\x00\x00' + \
        b'\x04\x00\x02\x00\x03\x00\x65\x6e\x30\x00\x09\x00\x01\x00\x06' + \
        b'\x00\x00\x00\x0c\x00\x2d\x00\x4d\x61\x63\x20\x4f\x53\x20\x58' + \
        b'\x20\x31\x30\x2e\x31\x33\x2e\x33\x2c\x20\x62\x75\x69\x6c\x64' + \
        b'\x20\x31\x37\x44\x34\x37\x20\x28\x44\x61\x72\x77\x69\x6e\x20' + \
        b'\x31\x37\x2e\x34\x2e\x30\x29\x00\x00\x00\x00\x00\x00\x00\x5c' + \
        b'\x00\x00\x00\x06\x00\x00\x00\x58\x00\x00\x00\x00\x00\x00\x00' + \
        b'\xc5\x78\x05\x00\xd5\x79\xf9\xc8\x36\x00\x00\x00\x36\x00\x00' + \
        b'\x00\x00' + \
        b'\x19\xcb\x58\xe8\x47\x9c\xf3\x87\xa2\x0c\x92\x08\x00\x45\x00' + \
        b'\x00\x28\x65\x79\x00\x00\x40\x06\x85\x50\xc0\xa8\x01\x25\x4a' + \
        b'\x7d\x83\xbc\xe5\xd2\x01\xbb\xf8\x67\xe8\xae\xda\xa9\x7f\xde' + \
        b'\x50\x10\x10\x00\xec\xa0\x00\x00' + \
        b'\x00\x00\x58\x00\x00\x00'
    return data
