package com.example.test;

import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.Statement;

public class FieldSensitivityTest {
    
    class UserDTO {
        public String name;
        public int id;
    }

    public void test(HttpServletRequest request, Connection conn) throws Exception {
        UserDTO user = new UserDTO();
        user.name = request.getParameter("name");
        user.id = 123; // Safe constant
        
        Statement stmt = conn.createStatement();

        // VULNERABLE: user.name is tainted
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + user.name + "'");

        // SAFE: user.id is clean
        stmt.executeQuery("SELECT * FROM users WHERE id = " + user.id);
    }
}
