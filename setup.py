from setuptools import setup

LONG_DESCRIPTION = """
# Hfinger - fingerprinting malware HTTP requests

Tool for fingerprinting malware HTTP requests. Based on Tshark and written in Python3. Working prototype stage :-)

It's main objective is to provide a representation of malware requests in a shorter form than printing whole request, 
but still human interpretable. This representation should be unique between malware families, 
what means that any fingerprint should be seen only for one particular family.

Project's website: [https://github.com/CERT-Polska/hfinger](https://github.com/CERT-Polska/hfinger).
"""

setup(
    name="hfinger",
    version="0.2.1",
    description="Hfinger - fingerprinting malware HTTP requests stored in pcap files",
    author="Piotr Białczak",
    author_email="piotrb@cert.pl",
    packages=["hfinger"],
    url="https://github.com/CERT-Polska/hfinger",
    include_package_data=True,
    install_requires=open("requirements.txt").read().splitlines(),
    python_requires=">=3.3",
    entry_points={
        "console_scripts": [
            "hfinger = hfinger.analysis:commandline_run",
        ]
    },
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    zip_safe=False,
    classifiers=[
        "Development Status :: 3 - Alpha",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python :: 3",
    ],
)
