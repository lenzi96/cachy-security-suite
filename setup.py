from setuptools import setup, find_packages

setup(
    name="cachy-security-suite",
    version="1.2.7",
    description="Modern PyQt6 graphical security & audit suite for Arch Linux & CachyOS",
    author="Julian",
    license="GPL-3.0-or-later",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "aur_scanner_gui": ["resources/*"],
    },
    entry_points={
        "console_scripts": [
            "cachy-security-suite=aur_scanner_gui.app:main",
            "aur-scanner-gui=aur_scanner_gui.app:main",
        ],
    },
    python_requires=">=3.9",
    install_requires=[
        "PyQt6>=6.0.0",
    ],
    classifiers=[
        "Environment :: X11 Applications :: Qt",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
)
