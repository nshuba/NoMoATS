from distutils.core import setup

setup(
    name='NoMoATS',
    version='0.1dev',
    packages=['nomoats',],
    license='GPL-3.0',
    long_description=open('README.md').read(),
    install_requires=['pcapng', 'frida==12.2.26', 'frida-tools==1.2.2'],
)
