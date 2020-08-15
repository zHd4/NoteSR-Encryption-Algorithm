package com.notesr.encryption.provider;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

class Hash {
    public static byte[] sha256(byte[] raw) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(raw);
    }

    public static byte[] randomSHA256Hash() throws NoSuchAlgorithmException {
        int randInt = (int) (Math.random() * 1000000000);
        return Hash.sha256(String.valueOf(randInt).getBytes());
    }
}
