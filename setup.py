#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2010-2021 OneLogin, Inc.
# MIT License

from setuptools import setup


setup(
    name='python-saml',
    version='2.10.0',
    description='Onelogin Python Toolkit. Add SAML support to your Python software using this library',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.7',
    ],
    author='OneLogin',
    author_email='support@onelogin.com',
    license='MIT',
    url='https://github.com/onelogin/python-saml',
    packages=['onelogin', 'onelogin/saml2'],
    include_package_data=True,
    package_data={
            'onelogin/saml2/schemas': ['*.xsd'],
    },
    package_dir={
        '': 'src',
    },
    test_suite='tests',
    install_requires=[
        'lxml>=3.3.5',
        'dm.xmlsec.binding==1.3.7',
        'isodate>=0.5.0',
        'defusedxml>=0.6.0',
    ],
    extras_require={
        'test': (
            'coverage>=3.6, <5.0',
            'freezegun==0.3.5',
            'flake8==3.6.0',
            'coveralls==1.1',
        ),
    },
    keywords='saml saml2 xmlsec django flask',
)
