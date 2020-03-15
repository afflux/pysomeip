#!/usr/bin/env python
import sys
import importlib.util
import pathlib

from setuptools import setup, find_packages

module_path = pathlib.Path(__file__).with_name('versioneer.py')
module_name = 'versioneer'
spec = importlib.util.spec_from_file_location(module_name, module_path)
versioneer = importlib.util.module_from_spec(spec)
sys.modules[module_name] = versioneer
spec.loader.exec_module(versioneer)

setup(
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
)
