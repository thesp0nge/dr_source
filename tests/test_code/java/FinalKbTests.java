package com.example.test;

import java.io.ObjectInputStream;
import java.io.InputStream;

public class FinalKbTests {
    public void secureReset() {
        // Safe token generation would use SecureRandom
    }

    public void vulnerable(InputStream is) throws Exception {
        // VULNERABLE: INSECURE_DESERIALIZATION (Refined)
        ObjectInputStream ois = new ObjectInputStream(is);
        ois.readObject();
    }
}
