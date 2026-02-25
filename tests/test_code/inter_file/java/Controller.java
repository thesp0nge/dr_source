// File 2: Controller.java
import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;

public class Controller {
    private DatabaseHelper helper = new DatabaseHelper();

    public void doGet(HttpServletRequest request, Connection conn) throws Exception {
        String id = request.getParameter("id");
        String sql = "SELECT * FROM users WHERE id = " + id;
        
        // This call crosses file boundaries
        helper.runQuery(sql, conn);
    }
}
