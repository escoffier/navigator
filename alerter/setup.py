# -*- coding: utf-8 -*-
"""Setup for the vegeta-alerter package.
"""
from setuptools import find_packages, setup

setup(
    name="vegeta-alerter",
    version="0.1.0",
    license="Proprietary",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "elastalert @ git+https://gitlab.com/androideighteen/elastalert.git@v0.2.1ae",
        "etcd3-py==0.1.6",
        "pymongo==3.9.0",
    ],
    entry_points={"console_scripts": ["vegeta-alerter=alerter.main:main"],},
)
