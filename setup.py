from setuptools import setup

setup(
    name="nihilist",
    version="1.0",
    url="https://github.com/caster0x00/Nihilist",
    author="Magama Bazarov",
    author_email="magamabazarov@mailbox.org",
    description="Cisco IOS Security Inspector",
    long_description=open('README.md', encoding="utf8").read(),
    long_description_content_type='text/markdown',
    license="Apache-2.0",
    keywords=['network security', 'config analyzer', 'cisco', 'cisco ios', 'hardening', 'networks'],
    install_requires=[
        'colorama',
        'netmiko',
    ],
    py_modules=['nihilist'],
    entry_points={
        "console_scripts": ["nihilist = nihilist:main"],
    },
    python_requires='>=3.11',
)