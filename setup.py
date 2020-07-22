#!/usr/bin/env python3

from setuptools import setup

setup(
    name='savedump',
    version="0.1.0",

    packages=[
        "savedump",
    ],

    entry_points={
        'console_scripts': ['savedump=savedump.savedump:main'],
    },

    author='Delphix Platform Team',
    author_email='serapheim@delphix.com',
    description='Archive linux crash dumps and cores',
    license='Apache-2.0',
    url='https://github.com/sdimitro/savedump',
)
