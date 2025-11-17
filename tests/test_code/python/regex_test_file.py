# This file is for testing the RegexAnalyzer optimization.
# It contains a string that *should* be caught by a
# JAVA-specific regex rule (JAVA-SQLI-002).
#
# Our new, smarter RegexAnalyzer should *not* run the Java
# rules on this .py file, and should therefore find NOTHING.


def a_python_function():
    # This string is a Java vulnerability, but in a Python file
    vulnerable_java_string = (
        'statement.execute("SELECT * FROM users WHERE id = " + userInput);'
    )
    pass
