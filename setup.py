from setuptools import find_packages, setup

requirements = open('requirements.txt').read().split("\n")
version = "0.2"

setup(
    name='pyeix',
    version=version,
    author='robert jakub',
    author_email='rj@project2.pl',
    description='eix schema tools',
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
