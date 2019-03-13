======
pcaper
======

.. image:: https://travis-ci.org/travis-ci/travis-web.svg?branch=master
    :target: https://travis-ci.org/travis-ci/travis-web

.. image:: https://codecov.io/gh/gaainf/pcaper/branch/master/graph/badge.svg
    :target: https://codecov.io/gh/gaainf/pcaper/

.. image:: https://img.shields.io/badge/python-2.7-blue.svg
    :target: https://www.python.org/downloads/release/python-270/

.. image:: https://img.shields.io/badge/python-3.5-blue.svg
    :target: https://www.python.org/downloads/release/python-350/

.. image:: https://img.shields.io/badge/python-3.6-blue.svg
    :target: https://www.python.org/downloads/release/python-360/

.. image:: https://img.shields.io/pypi/l/pcaper.svg
    :target: https://github.com/gaainf/pcaper/blob/master/LICENSE

The package helps to assemble and iterate HTTP requests.
Pcaper provides class to read traffic files in pcap or har formats, executable converters - `pcap2txt` and `har2txt`.
`PcapParser` based on `dpkt <https://github.com/kbandla/dpkt/>`_. `HarParser` uses built-in json package.

`pcaper` extends dpkt.http.Request class. Following fields of HTTP request are available:

- `timestamp` - timestamp of the last packet of original HTTP request
- `src` - source IP address
- `dst` - destination IP address
- `sport` - source TCP port
- `dport` - destination TCP port
- `method` - HTTP request method
- `version` - HTTP protocol version
- `uri` - HTTP request URI
- `headers` - ordered dictionary of HTTP headers
- `origin_headers` - ordered dictionary HTTP headers with case sensetive names
- `body` - HTTP request body
- `origin` - original HTTP request

************
Installation
************

.. code:: python

    pip install pcaper

******
Import
******

.. code:: python

    import pcaper
    pcap_parser = pcaper.PcapParser()
    har_parser = pcaper.HarParser()

********
Examples
********

Iterate HTTP requests
*********************

Read pcap file, assemble and iterate HTTP requests

.. code:: python

    from pcaper import PcapParser

    pcap_parser = PcapParser()
    params = {
        'input': 'file.pcap',
    }
    for request in pcap_parser.read_pcap(params):
        print(request.origin)

.. code:: python

    from pcaper import HarParser

    har_parser = HarParser()
    params = {
        'input': 'file.har'
    }
    for request in har_parser.read_har(params):
        print(request.origin)

Extract separate HTTP request headers
*************************************

You can extract header by name

.. code:: python

    reader = pcaper.PcapParser()
    params = {
        'input': 'file.pcap'
    }
    for request in reader.read_pcap(params):
        print(request.headers['host'])
        print(request.headers['user-agent'])

Filter TCP/IP packets
*********************

It is possible to filter out excess packets

.. code:: python

    reader = pcaper.PcapParser()
    params = {
        'input': 'file.pcap',
        'filter': 'tcp.dst == 1.1.1.1'
    }
    for request in reader.read_pcap(params):
        print(request.origin)


You can combine tcp and ip filters in dpkt style

.. code:: python

    reader = pcaper.PcapParser()
    params = {
        'input': 'file.pcap',
        'filter': '(ip.src == 10.4.0.136 or ip.dst == 10.1.40.61) and tcp.dport == 8888'
    }
    for request in reader.read_pcap(params):
        print(request.origin)

It is possible to use excluding filter in dpkt style

.. code:: python

    reader = pcaper.PcapParser()
    params = {
        'input': 'file.pcap',
        'filter': 'tcp.dport != 8888 and ip.dst != 10.1.40.61'
    }
    for request in reader.read_pcap(params):
        print(request.origin)

Note
****

New `pcapng format <https://pcapng.github.io/pcapng//>`_ is not supported by `dpkt <https://github.com/kbandla/dpkt/>`_ package,
but you can convert input file from `pcapng` to `pcap` format
with standard utility, which is installed with `wireshark <https://www.wireshark.org//>`_ package.

.. code:: bash

    mergecap file.pcapng -w out.pcap -F pcap

*******
Scripts
*******

pcap2txt
********

The `pcap2txt` script is installed to Python directory
and can be executed directly in command line

It simplify parsing of pcap files. Just extract HTTP requests
including its headers and body and print out complete data to console or file.

Print HTTP requests from pcap file:

.. code:: bash

    pcap2txt file.pcap

Filter TCP/IP packets, extract HTTP requests and write to external file:

.. code:: bash

    pcap2txt -f "tcp.dport == 8080 and ip.dst != 10.10.10.10" -o file.out file.pcap

Filter HTTP packets

.. code:: bash

    pcap2txt -F '"rambler.ru" in http.uri' file.pcap

You can use logical expressions in filters

.. code:: bash

    pcap2txt -F '"keep-alive" in http.headers["connection"] or "Keep-alive" in http.headers["connection"]' file.pcap

Standard Python string functions over HTTP request headers

.. code:: bash

    pcap2txt -F '"keep-alive" in http.headers["connection"].lower()' file.pcap

Use excluding filters also

.. code:: bash

    pcap2ammo -F '"rambler.ru" not in http.uri' file.pcap

Print statistics about counted requests:

.. code:: bash

    pcap2txt -f "ip.src == 10.10.10.10" -S file.pcap

    Stats:
        total: 1
        complete: 1
        incorrect: 0
        incomplete: 0

har2txt
*******

The `har2txt` script is installed to Python directory
and can be executed directly in command line

It simplify parsing of har files. Just extract HTTP requests
including its headers and body and print out complete data to console or file.

Print HTTP requests from har file:

.. code:: bash

    har2txt file.har

Filter HTTP packets

.. code:: bash

    har2txt -F 'http.verision == "1.1"' file.har

Use excluding filters also

.. code:: bash

    har2txt -F '"rambler.ru" not in http.uri' file.har

Filter packets with destination IP. 
`pcaper` extracts data from har file,
which contains destination IP (`dst` filed), but doesn't contain source IP, source and destination ports.

.. code:: bash

    har2txt -F 'http.dst == "1.1.1.1"' file.har

Print statistics about counted requests:

.. code:: bash

    har2txt -S -F 'http.dst == "10.10.10.10' file.har

    Stats:
        total: 1
        complete: 1
        incorrect: 0
        incomplete: 0
