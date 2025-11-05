// A safe file that should produce 0 findings.
public class Safe {

    public void goodMethod(String input) {
        String safeQuery = "SELECT * FROM users WHERE username = ?";
        
        // This is a PreparedStatement, which is the correct, safe way.
        PreparedStatement stmt = connection.prepareStatement(safeQuery);
        stmt.setString(1, input);
        stmt.executeQuery();
    }

    public void anotherMethod() {
        System.out.println("Hello, world!");
    }
}
