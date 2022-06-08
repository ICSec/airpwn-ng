#!/usr/bin/python3

from setuptools import setup

setup(
    name = 'airpwn-ng',
    version = '2.0.4',
    author = 'stryngs and Jack64',
    packages = ['airpwn_ng', 'airpwn_ng.lib'],
    include_package_data = True,
    url = 'https://github.com/ICSec/airpwn-ng',
    license ='GNU General Public License v3',
    keywords = '802.11 Packet Injection',
    description='Packet injection for wifi; simplified.',
    long_description = 'Packet injection for wifi; simplified.',
    install_requires = ['scapy==2.4.5']
)
