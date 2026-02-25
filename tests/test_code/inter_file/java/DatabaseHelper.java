// File 1: DatabaseHelper.java
import java.sql.Statement;
import java.sql.Connection;

public class DatabaseHelper {
    public void runQuery(String query, Connection conn) throws Exception {
        Statement stmt = conn.createStatement();
        // The sink is here
        stmt.executeQuery(query);
    }
}
