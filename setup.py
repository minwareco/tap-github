#!/usr/bin/env python
import os 

from setuptools import setup, find_packages

setup(name='tap-github',
      version='1.10.0',
      description='Singer.io tap for extracting data from the GitHub API',
      author='Stitch',
      url='http://singer.io',
      classifiers=['Programming Language :: Python :: 3 :: Only'],
      py_modules=['tap_github'],
      install_requires=[
          'singer-python==5.12.1',
          'requests==2.20.0',
          'psutil==5.8.0',
          'debugpy==1.5.1',
          'PyJWT==2.3.0',
          'cryptography==36.0.2',
          'gitlocal@git+https://{}@github.com/minwareco/gitlocal.git@cffdf75345db9024b1026cb2b2ea31e35d135ce0'.format(os.environ.get("GITHUB_TOKEN", ""))
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
