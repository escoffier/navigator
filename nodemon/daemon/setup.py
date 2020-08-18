from setuptools import setup, find_packages

import os

base_dir = os.path.dirname(__file__)

setup(
    name="daemon",
    version="1.0.0",
    description="A daemon running in a k8s daemonset to capture the runtime info",
    author="Container Security Group",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Application Frameworks",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
    ],
    keywords="daemon daemonset",
    packages=find_packages(),
    data_files=[],
    install_requires=["Click==7.0", "etcd3-py==0.1.6",],
    include_package_data=True,
    entry_points={"console_scripts": ["vegeta-daemon=daemon.main:main",]},
)
