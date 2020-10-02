# Copyright (c) 2017 Interactive Intelligence, Inc.

from setuptools import setup, find_packages

install_reqs = [
    'mohawk',
    'requests[security]',
    'retrying'
]

setup(name='threatstack',
      version='1.2.1',
      description='A Python client for the Threat Stack API',
      license='MIT License',
      author='Genesys Cloud Security Team',
      author_email='danny.rappleyea@genesys.com',
      maintainer='Genesys Labs',
      url='https://github.com/purecloudlabs/threatstack-python-client',
      install_requires=install_reqs,
      classifiers=[
          'Development Status :: 4 - Beta',
          'Intended Audience :: Developers',
          'Intended Audience :: Information Technology',
          'Intended Audience :: System Administrators',
          'License :: OSI Approved :: MIT License',
          'Natural Language :: English',
          'Operating System :: POSIX :: Linux',
          'Programming Language :: Python',
          'Topic :: Security',
      ],
      packages=find_packages()
)
