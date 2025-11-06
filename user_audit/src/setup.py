from setuptools import setup, find_packages

setup(
    name="user-audit",
    version="0.0.1",
    description="User account auditing tool for Linux (CLI)",
    long_description="Small CLI to audit /etc/passwd accounts, lastlog, sudo membership, and home sizes.",
    author="Your Name",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "rich>=12.0",
        "pyfiglet>=0.8"
    ],
    entry_points={
        "console_scripts": [
            "user-audit=user_audit.cli:main",
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: POSIX :: Linux",
    ],
)
