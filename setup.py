# Copyright (c) 2017 Interactive Intelligence, Inc.

from setuptools import setup, find_packages

install_reqs = [
    'requests[security]',
    'retrying'
]

setup(name='threatstack',
      version='1.1.1',
      description='A Python client for the Threat Stack API',
      license='MIT License',
      author='PureCloud Security Team',
      author_email='george.vauter@genesys.com',
      maintainer='Genesys Labs',
      url='https://github.com/MyPureCloud/threatstack-python-client',
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
