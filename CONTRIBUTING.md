# Contributing to dr_source

First off, thank you for considering contributing! We're excited you're interested in helping make dr_source a more powerful and accurate static analysis tool. All contributions, from bug reports to new feature ideas and code patches, are welcome.

## Code of Conduct

This project and everyone participating in it is governed by the dr_source Code of Conduct. By participating, you are expected to uphold this code.

## How to Get Started

Ready to jump in? Here's how to set up your local development environment.

1. Fork & Clone

* Fork the repository on GitHub.
* Clone your fork locally:
```
git clone [https://github.com/thesp0nge/dr_source.git](https://github.com/thesp0nge/dr_source.git)
cd dr_source
```

2. Create a Virtual Environment
We highly recommend using a Python virtual environment to manage dependencies.

```
python -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
```

3. Install in Editable Mode
Install the project in "editable" mode (-e). This is essential as it uses pyproject.toml to register your plugins (JavaAstAnalyzer, RegexAnalyzer, etc.) so the scanner can find them.
```
pip install -e .
```

4. Install Test Dependencies
You'll need pytest to run the test suite.
```
pip install pytest
```

5. Run the Tests
Before you make any changes, run the full test suite to make sure your environment is set up correctly.
```
pytest
```

If all tests pass, you're ready to start coding!

## How to Contribute: Two Paths

There are two main ways to contribute to dr_source, depending on your goal.

### Path 1: Add or Improve a Rule (The Easy Way)

This is the best way to get started. Your contribution will be to edit the knowledge_base.yaml file to make an existing plugin smarter.

1. Open the Knowledge Base:
2. All detection logic lives in dr_source/config/knowledge_base.yaml.

Add Your Rule:

* To add a simple regex rule: Find the vulnerability (e.g., WEAK_CRYPTO) and add a new entry under general_regex_patterns or language_specific:[lang]:regex_patterns.
```
WEAK_CRYPTO:
  # ...
  language_specific:
    python:
      regex_patterns:
        - id: "PY-CRYPTO-004"
          message: "Use of insecure blowfish cipher."
          severity: "HIGH"
          pattern: |
            (?i)from\s+Crypto\.Cipher\s+import\s+Blowfish
```

* To add an AST-based rule: Find the vulnerability (e.g., SQL_INJECTION) and add your new method name to the ast_sources or ast_sinks list for the correct language.
```
SQL_INJECTION:
  # ...
  language_specific:
    python:
      ast_sources:
        - "request.args.get"
        - "request.form.get" # <-- Your new source
```

3. Write a Test:

* Add a small code snippet to tests/test_code/ that uses your new rule (e.g., tests/test_code/python/vulnerable_blowfish.py).
* Add a new test method to the appropriate test file (e.g., tests/plugins/test_regex_analyzer.py) that scans your new file and asserts that your new rule is found.

### Path 2: Add a New Analyzer Plugin (The Advanced Way)

This is for adding a major new feature, like support for a new language (e.g., Go, C#) or a new analysis technique.

1. Create the Plugin Package: Create a new directory for your plugin, e.g., dr_source/plugins/golang/.

2. Implement the API: Create a plugin.py file in your new directory. Inside, create a class that inherits from AnalyzerPlugin (defined in dr_source/api.py) and implements its three required methods:
```
from dr_source.api import AnalyzerPlugin, Vulnerability

class GoLangAstAnalyzer(AnalyzerPlugin):
    @property
    def name(self) -> str:
        return "GoLang AST Analyzer"

    def get_supported_extensions(self) -> List[str]:
        return [".go"]

    def analyze(self, file_path: str) -> List[Vulnerability]:
        findings = []
        # ... your analysis logic here ...
        return findings
```

3. Register the Plugin: Open pyproject.toml and add your new plugin to the [project.entry-points."dr_source.plugins"] section:
```
[project.entry-points."dr_source.plugins"]
java_ast = "dr_source.plugins.java.plugin:JavaAstAnalyzer"
regex_all = "dr_source.plugins.regex.plugin:RegexAnalyzer"
python_ast = "dr_source.plugins.python.plugin:PythonAstAnalyzer"
golang_ast = "dr_source.plugins.golang.plugin:GoLangAstAnalyzer" # <-- Your new plugin
```
4. Re-install: Run pip install -e . again to register the new plugin.
5. Write Tests: Add a new test file in tests/plugins/ (e.g., test_golang_ast_analyzer.py) to validate your new plugin.

## Submitting Your Change

1. Create a Branch: Start from the main branch and create a descriptive branch name.
```
git checkout main
git pull upstream main  # (Assuming 'upstream' is the main dr_source repo)
git checkout -b feature/add-python-ssrf-rule
```

2. Make Your Changes & Commit: Write your code and your tests. Commit your changes with a clear message.
3. Run Tests: Do not submit a Pull Request until all tests pass!
```
pytest
```

4. Push and Open a Pull Request: Push your branch to your fork and open a Pull Request (PR) against the main branch of the dr_source repository.

5. Describe Your PR: Write a clear description of what you changed and why. If you fixed an issue, link to it (e.g., "Fixes #42").

Thank you for contributing!
