package com.example.demo;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.sql.Connection;
import java.sql.Statement;

@RestController
public class SpringController {

    @GetMapping("/search")
    public String search(@RequestParam("q") String query, Connection conn) {
        try {
            Statement stmt = conn.createStatement();
            // VULNERABLE: 'query' comes from @RequestParam annotation
            stmt.executeQuery("SELECT * FROM products WHERE name = '" + query + "'");
        } catch (Exception e) {
            return "Error";
        }
        return "Done";
    }

    @GetMapping("/safe")
    public String safe(@RequestParam("id") int id) {
        // SAFE: constant propagation should handle this if id was a string, 
        // but here it's just to check if the engine works.
        return "ID: " + id;
    }
}
