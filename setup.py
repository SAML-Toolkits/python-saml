#! /usr/bin/env python
# -*- coding: utf-8 -*-

# MIT License

from setuptools import setup


setup(
    name='python-saml',
    version='2.13.0',
    description='Saml Python Toolkit. Add SAML support to your Python software using this library',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.7',
    ],
    author='SAML-Toolkits',
    author_email='contact@iamdigitalservices.com',
    maintainer='Sixto Martin',
    maintainer_email='sixto.martin.garcia@gmail.com',
    license='MIT',
    url='https://github.com/SAML-Toolkits/python-saml',
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
        'lxml>=4.6.5, !=4.7.0',
        'dm.xmlsec.binding==1.3.7',
        'isodate>=0.6.1',
        'defusedxml>=0.7.1',
    ],
    extras_require={
        'test': (
            'coverage>=4.5, <5.0',
            'freezegun>=0.3.5, <0.4',
            'flake8>=3.6.0, < 4.0',
        ),
    },
    keywords='saml saml2 xmlsec django flask',
)
