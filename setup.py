import os
from os.path import abspath, dirname, join
from setuptools import find_packages, setup

requirements = open('requirements.txt').read().split("\n")
current_dir = dirname(abspath(__file__))
exec(open(join(current_dir, "pyeix/__init__.py")).read())
version = __version__

setup(
    name='pyeix',
    version=version,
    author='robert jakub',
    author_email='rj@project2.pl',
    description='eix schema tools',
    long_description='',
    license='MIT',
    scripts=['scripts/eix'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Internet',
    ],
    packages=find_packages(),
    package_data={"pyeix": ["schema/*"]},
    include_package_data=True,
    install_requires=requirements,
    zip_safe=True
)
