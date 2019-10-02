#!/usr/bin/env python

from setuptools import setup, find_packages
import versioneer

CLASSIFIERS = [
    "Development Status :: 4 - Beta",
    "Operating System :: OS Independent",
    "Programming Language :: Python",
]

extra = {}
extra['install_requires'] = open('requirements.txt').read().splitlines()

setup(
    name='someip',
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    author='Kjell Braden <afflux@pentabarf.de>',
    platforms='any',
    classifiers=CLASSIFIERS,
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'someip-monitor-offers = someip.sd:main',
        ],
    },
    **extra
)

