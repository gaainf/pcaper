#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2018 Alexander Grechin
#
# Licensed under the BSD 3-Clause license.
# See LICENSE file in the project root for full license information.
#

"""Setup module"""

from setuptools import setup, find_packages

with open('README.rst') as f:
    long_readme = f.read()

setuptools_kwargs = {
    'install_requires': [
        'dpkt>=1.9.1',
        'flake8>=3.5.0',
        'six>=1.11.0'
    ],
    'setup_requires': 'pytest-runner',
    'tests_require': [
        'pytest>=2.7',
        'pytest-cov>=2.6.0'
    ],
}

PACKAGE_NAME = 'pcaper'
AUTHOR = 'Alexander Grechin'
AUTHOR_EMAIL = 'infinum@mail.ru'
LICENSE = 'BSD'
VERSION = '1.0.0'

setup(
    name=PACKAGE_NAME,
    version=VERSION,
    packages=find_packages(exclude=('tests', 'docs')),
    description='Read pcap and assemble HTTP requests',
    long_description=long_readme,
    keywords='traffic pcap utilities tcpdump tshark wireshark',
    author=AUTHOR,
    author_email=AUTHOR_EMAIL,
    download_url='https://github.com/gaainf/pcaper',
    url='https://github.com/gaainf/pcaper',
    license='BSD-3-Clause',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Operating System :: OS Independent',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Software Development',
        'Topic :: Utilities'
    ],
    **setuptools_kwargs
)
