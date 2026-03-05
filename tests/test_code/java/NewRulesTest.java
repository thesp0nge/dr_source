package com.example.test;

import javax.servlet.http.HttpServletRequest;
import java.util.logging.Logger;

public class NewRulesTest {
    private static final Logger logger = Logger.getLogger(NewRulesTest.class.getName());

    public void testAll(HttpServletRequest request) throws Exception {
        String input = request.getParameter("input");

        // VULNERABLE: LOG_INJECTION
        logger.info("Received input: " + input);

        // VULNERABLE: INSECURE_REFLECTION
        Class.forName(input);

        String password = "secret_password";
        // VULNERABLE: PII_LEAKAGE
        System.out.println("User password is: " + password);
    }
}
