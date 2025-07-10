#!/usr/bin/env python
import os 

from setuptools import setup, find_packages

UTILS_VERSION = "52a7ce3dbe9b96a6a09e9e9ce029b2840a9eb937"

setup(name='tap-github',
      version='1.10.0',
      description='Singer.io tap for extracting data from the GitHub API',
      author='Stitch',
      url='http://singer.io',
      classifiers=['Programming Language :: Python :: 3 :: Only'],
      py_modules=['tap_github'],
      install_requires=[
          'singer-python>=6',
          'requests>=2',
          'psutil==5.8.0',
          'debugpy==1.5.1',
          'PyJWT==2.8.0',
          'cryptography==42.0.1',
          'minware_singer_utils@git+https://{}github.com/minwareco/minware-singer-utils.git@{}'.format(
              "{}@".format(os.environ.get("GITHUB_TOKEN")) if os.environ.get("GITHUB_TOKEN") else "",
              UTILS_VERSION
          )
      ],
      extras_require={
          'dev': [
              'pylint',
              'ipdb',
              'nose',
          ]
      },
      entry_points='''
          [console_scripts]
          tap-github=tap_github:main
      ''',
      packages=['tap_github'],
      package_data = {
          'tap_github': ['tap_github/schemas/*.json']
      },
      include_package_data=True
)
