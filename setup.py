#!/usr/bin/env python

from distutils.core import setup

setup(name="pcap-reassembler",
      version='0.1',
      description='Reassembles UDP/TCP packets into application layer messages',
      author='Fredrik Appelros, Carl Ekerot',
      author_email='fredrik.appelros@gmail.com, kalle@implode.se',
      url='https://github.com/FredrikAppelros/pcap-reassembler',
      py_modules=['pcap_reassembler'],
      install_requires=['pylibpcap']
      )

