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

setup_requires = [
    "pytest-runner",
]

requires = [
    'dpkt>=1.9.1',
    'flake8>=3.5.0',
]

test_requires = [
    'pytest>=2.7',
    'pytest-cov>=2.6.0',
]

package_name = 'pcaper'
package = __import__(package_name)

setup(
    name=package_name,
    version=package.__version__,
    packages=find_packages(exclude=('tests', 'docs')),
    description='Read pcap and assemble HTTP requests',
    long_description=long_readme,
    keywords='traffic pcap utilities tcpdump tshark wireshark',
    author=package.__author__,
    author_email=package.__author_email__,
    download_url='https://github.com/gaainf/pcaper',
    url='https://github.com/gaainf/pcaper',
    license='BSD-3-Clause',
    install_requires=requires,
    setup_requires=setup_requires,
    tests_require=test_requires,
    test_suite='tests',
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
)
