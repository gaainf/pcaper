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

    params1 = {
        'input': 'file.pcap',
        'filter': 'tcp.dport == 80 and ip.src == 1.1.1.1'
    }

    params2 = {
        'input': 'file.pcap',
        'filter': 'tcp.sport == 8888 or ip.dst == 2.2.2.2'
    }

Notes
*****************************

New `pcapng format <https://pcapng.github.io/pcapng//>`_ is not supported by `dpkt <https://github.com/kbandla/dpkt/>`_ package,
but you can convert input file from `pcapng` to `pcap` format
with standard utility, which is installed with `wireshark <https://www.wireshark.org//>`_ package.

.. code:: bash

    mergecap file.pcapng -w out.pcap -F pcap
