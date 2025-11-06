// This file is for testing the RegexAnalyzer on Java code
public class RegexSqli {

    public void badRegexMethod(Statement statement, String userInput) {
        try {
            // This line matches rule JAVA-SQLI-002
            statement.execute("SELECT * FROM users WHERE id = '" + userInput + "'");
        } catch (Exception e) {
            // handle
        }
    }
}
