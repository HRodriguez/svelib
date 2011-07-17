from setuptools import setup, find_packages
import sys, os

version = '0.0.1'

setup(name='PloneVoteCryptoLib',
      version=version,
      description="Basic cryptographic library for the PloneVote verifiable online voting system.",
      long_description="""\
This library provides all basic cryptographic operations required by the PloneVote verifiable online voting system. (ToDo: Improve description)""",
      classifiers=[
      		'Development Status :: 1 - Planning',
      		'Intended Audience :: Developers',
      		'License :: OSI Approved :: MIT License',
      		'Natural Language :: English',
      		'Operating System :: MacOS :: MacOS X',
      		'Operating System :: Microsoft :: Windows',
      		'Operating System :: POSIX :: Linux',
      		'Programming Language :: Python :: 2.4',
      		'Programming Language :: Python :: 2.6',
      		'Topic :: Security :: Cryptography'], # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
      keywords='cryptography, voting, library, PloneVote',
      author='Lazaro Clapp',
      author_email='lazaro.clapp@gmail.com',
      url='http://ToDo/set/a/web/page.html',
      license='MIT',
      packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
      include_package_data=True,
      zip_safe=False,
      install_requires=[
      	  'pycrypto >= 2.1.0'
          # -*- Extra requirements: -*-
      ],
      entry_points="""
      # -*- Entry points: -*-
      """,
      )
