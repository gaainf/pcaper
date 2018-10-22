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


********
Examples
********

Iterate HTTP request
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

It is possible to combine tcp and ip filters in dpkt style

.. code:: python

    reader = pcaper.HTTPRequest()
    params = {
        'input': 'file.pcap',
        'filter': 'tcp.dport == 80 and ip.src == 1.1.1.1'
    }
    for request in reader.read_pcap(params):
        print request['origin']

