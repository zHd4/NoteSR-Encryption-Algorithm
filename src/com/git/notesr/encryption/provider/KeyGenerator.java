package com.git.notesr.encryption.provider;

import java.util.Arrays;
import java.security.NoSuchAlgorithmException;
import com.git.notesr.encryption.provider.exceptions.CryptoKeyException;

public class KeyGenerator {
    private final int size;

    public KeyGenerator(int size) {
        this.size = size;
    }

    public byte[] createKey() throws NoSuchAlgorithmException {
        String passphrase = new String(Hash.randomSHA256Hash());
        return generate(passphrase);
    }

    public byte[] createKey(String passphrase) throws CryptoKeyException, NoSuchAlgorithmException {
        if(passphrase != null) {
            if(passphrase.isEmpty()) {
                throw new CryptoKeyException("Key cannot be empty");
            }
        } else {
            throw new CryptoKeyException("Key cannot be null");
        }

        return generate(passphrase);
    }

    private byte[] generate(String keySource) throws NoSuchAlgorithmException {
        byte[] key = new byte[0];
        byte offset = keySource.getBytes()[0];
        byte[] hashNext = Hash.sha256(keySource.getBytes());

        while (key.length < size) {
            for (int i = 0; i < hashNext.length; i++) {
                hashNext[i] += offset;
            }

            key = Arrays.copyOf(hashNext, key.length + hashNext.length);
            hashNext = Hash.sha256(hashNext);
        }

        key = Arrays.copyOf(key, size);

        return key;
    }
}
