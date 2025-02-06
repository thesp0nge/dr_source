from setuptools import setup, find_packages

setup(
    name="drsource",
    version="0.16.0",
    packages=find_packages(),
    install_requires=["click", "javalang", "beautifulsoup4", "scikit-learn", "PyYAML"],
    entry_points={
        "console_scripts": [
            "dr_source=dr_source.cli:main",
        ],
    },
    scripts=["bin/dr_source"],
    author="Paolo Perego",
    description="Java and JSP Vulnerability Static Analyzer",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
)
