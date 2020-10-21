from setuptools import setup

setup(
    name="hfinger",
    version="0.1.0",
    description="Hfinger - fingerprinting HTTP requests stored in pcap files",
    author="Piotr Bialczak",
    author_email="piotrb@cert.pl",
    packages=["hfinger", "hfinger.configs"],
    package_data={"hfinger": ["configs/*.json", "configs/*.txt"]},
    install_requires=["fnvhash", "python-magic"],
    zip_safe=False,
)
