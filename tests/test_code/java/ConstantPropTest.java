import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.Statement;

public class ConstantPropTest {
    public void testSql(HttpServletRequest request, Connection conn) throws Exception {
        String userId = request.getParameter("id");
        Statement stmt = conn.createStatement();

        // VULNERABLE: Input utente diretto (Deve essere rilevato)
        stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);

        // SAFE: Costruito con costanti (Deve essere ignorato)
        String table = "logs";
        String safeQuery = "SELECT * FROM " + table;
        stmt.executeQuery(safeQuery);

        // SAFE: Stringa letterale diretta (Deve essere ignorato)
        stmt.executeQuery("SELECT 1 FROM dual");
    }
}
