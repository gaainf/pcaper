==============================
pcaper
==============================

.. image:: https://travis-ci.org/travis-ci/travis-web.svg?branch=master
    :target: https://travis-ci.org/travis-ci/travis-web

.. image:: https://codecov.io/gh/gaainf/pcaper/branch/master/graph/badge.svg
    :target: https://codecov.io/gh/gaainf/pcaper/

Pcaper provides class to read pcap file, assemble and iterate HTTP requests.
The package based on `dpkt <https://github.com/kbandla/dpkt/>`_.

************
Installation
************
.. code:: python

    pip install pcaper

************
Import
************
.. code:: python

    import pcaper
    reader = pcaper.HTTPRequest()

or

.. code:: python

    from pcaper import HTTPRequest
    reader = HTTPRequest()

********
Examples
********

Iterate HTTP requests
*****************************

Read pcap file, assemble and iterate HTTP requests

.. code:: python

    reader = pcaper.HTTPRequest()
    params = {
        'input': 'file.pcap',
    }
    for request in reader.read_pcap(params):
        print request['origin']

Extract http headers
*****************************

You can extract header by name

.. code:: python

    reader = pcaper.HTTPRequest()
    params = {
        'input': 'file.pcap',
    }
    for request in reader.read_pcap(params):
        print request['headers']['host']
        print request['headers']['content-length']

Filter packets
*****************************

It is possible to filter out excess packets

.. code:: python

    reader = pcaper.HTTPRequest()
    params = {
        'input': 'file.pcap',
        'filter': 'tcp.dst == 1.1.1.1'
    }
    for request in reader.read_pcap(params):
        print request['origin']


You can combine tcp and ip filters in dpkt style

.. code:: python

    reader = pcaper.HTTPRequest()
    params = {
        'input': 'file.pcap',
        'filter': '(ip.src == 10.4.0.136 or ip.dst == 10.1.40.61) and tcp.dport == 8888'
    }
    for request in reader.read_pcap(params):
        print request['origin']

It is possible to use excluding filter in dpkt style

.. code:: python

    reader = pcaper.HTTPRequest()
    params = {
        'input': 'file.pcap',
        'exfilter': 'tcp.dport == 8888 and ip.dst == 10.1.40.61'
    }
    for request in reader.read_pcap(params):
        print request['origin']

Notes
*****************************

New `pcapng format <https://pcapng.github.io/pcapng//>`_ is not supported by `dpkt <https://github.com/kbandla/dpkt/>`_ package,
but you can convert input file from `pcapng` to `pcap` format
with standard utility, which is installed with `wireshark <https://www.wireshark.org//>`_ package.

.. code:: bash

    mergecap file.pcapng -w out.pcap -F pcap

************
Scripts
************

parse_http
**********

The `parse_http` script is installed to Python directory
and can be executed directly in command line

It simplify parsing of pcap files. Just extract HTTP requests
including its headers and body and print out complete data to console or file.

Print HTTP requests from pcap file:

.. code:: bash

    parse_http file.pcap

Filter HTTP requests and write to external file:

.. code:: bash

    parse_http -f "tcp.dport == 8080" -e "ip.dst == 10.10.10.10" -o file.out file.pcap

Print statistics about counted requests:

.. code:: bash

    parse_http -f "ip.src == 10.10.10.10" -S file.pcap

    Stats:
        total: 1
        complete: 1
        incorrect: 0
        incomplete: 0
