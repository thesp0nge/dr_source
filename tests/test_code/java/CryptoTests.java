package com.example.test;

import java.security.MessageDigest;
import javax.crypto.Cipher;

public class CryptoTests {
    public void testInsecure() throws Exception {
        // VULNERABLE: WEAK_CRYPTO (MD5)
        MessageDigest md = MessageDigest.getInstance("MD5");
        
        // VULNERABLE: WEAK_CRYPTO (AES-ECB)
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
    }

    public void testSafe() throws Exception {
        // SAFE
        MessageDigest md = MessageDigest.getInstance("SHA-256");
    }
}
