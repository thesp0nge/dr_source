package com.example.test;

import java.io.ObjectInputStream;
import java.io.ByteArrayInputStream;
import javax.servlet.http.HttpServletRequest;

public class RceTests {
    public void testDeserialization(HttpServletRequest request) throws Exception {
        String data = request.getParameter("data");
        byte[] bytes = data.getBytes();
        
        // VULNERABLE: INSECURE_DESERIALIZATION
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));
        ois.readObject();
    }
}
