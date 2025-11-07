from setuptools import setup, find_packages

setup(
    name="dr_source",
    version="0.90.0",
    packages=find_packages(),
    install_requires=["click", "javalang", "beautifulsoup4", "scikit-learn", "PyYAML"],
    entry_points={
        "console_scripts": [
            "dr_source=dr_source.cli:main",
        ],
        "dr_source.plugins": [
            "java_ast = dr_source.plugins.java.plugin:JavaAstAnalyzer",
            "regex_all = dr_source.plugins.regex.plugin:RegexAnalyzer",
        ],
    },
    include_package_data=True,
    zip_safe=False,
    scripts=["bin/dr_source"],
    author="Paolo Perego",
    description="DRSource is an extensible, multi-language static analysis tool designed to detect vulnerabilities in source code.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
)
