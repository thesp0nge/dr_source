// A vulnerable file to test SQL Injection detection.
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class Sqli {

    public void badMethod(HttpServletRequest request, Statement statement) {
        
        // This is our Taint Source
        String userId = request.getParameter("userId");
        
        // This is a vulnerable query concatenation
        String sqlQuery = "SELECT * FROM users WHERE userId = '" + userId + "'";
        
        try {
            // This is our Taint Sink
            statement.executeQuery(sqlQuery); 
        } catch (Exception e) {
            // handle
        }
    }
}
