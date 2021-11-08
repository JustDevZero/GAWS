#!/usr/bin/env python

"""
    GAWS
    ==========

    GAWS wraps aws commands in a google sign on service.

"""

import sys

from setuptools import setup

if sys.version_info.major < 3:
    raise RuntimeError(
        'GAWS does not support Python 2.x anymore. '
        'Please use Python 3 or do magic.')

setup()
