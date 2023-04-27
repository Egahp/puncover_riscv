#!/usr/bin/env python
import os
from pathlib import Path

from setuptools import setup, find_packages, Command

ROOTDIR = Path(__file__).parent

__version__ = None  # Overwritten by executing version.py.
with open(ROOTDIR / "puncover_riscv/version.py") as f:
    exec(f.read())


with open(ROOTDIR / "requirements-test.txt") as f:
    tests_require = list(filter(lambda x: not x.strip().startswith('-r'), f.readlines()))

with open(ROOTDIR / "requirements.txt") as f:
    requires = f.readlines()


class CleanCommand(Command):
    """Custom clean command to tidy up the project root."""

    # http://stackoverflow.com/a/3780822/196350
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        os.system("rm -vrf ./build ./dist ./*.pyc ./*.tgz ./*.egg-info")


setup(
    name="puncover_riscv",
    version=__version__,
    description="Analyses RISCV C/C++ build output for code size, static variables, and stack usage.",
    long_description=open("README.rst").read(),
    long_description_content_type="text/x-rst",
    url="https://github.com/Egahp/puncover_riscv",
    download_url="https://github.com/Egahp/puncover_riscv/tarball/%s" % __version__,
    author="Egahp",
    license="MIT",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    packages=find_packages(exclude=["tests", "tests.*"]),
    include_package_data=True,
    zip_safe=False,
    entry_points={"console_scripts": ["puncover_riscv = puncover_riscv.puncover_riscv:main"]},
    install_requires=requires,
    tests_require=tests_require,
    cmdclass={
        "clean": CleanCommand,
    },
    # TODO: https://github.com/HBehrens/puncover_riscv/issues/36
    #  Fix Python 3.5
    python_requires=">=3.6",
)
