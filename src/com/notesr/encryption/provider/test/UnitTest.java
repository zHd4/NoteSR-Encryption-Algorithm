package com.notesr.encryption.provider.test;

import org.junit.Test;

import com.notesr.encryption.provider.KeyGenerator;
import com.notesr.encryption.provider.CryptoProvider;
import com.notesr.encryption.provider.exceptions.BadCryptException;
import com.notesr.encryption.provider.exceptions.CryptoKeyException;

import java.security.NoSuchAlgorithmException;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class UnitTest {
    private static final int KEY_SIZE = 128;
    private static final int IV_SIZE = 32;

    @Test
    public void testEncryption() throws NoSuchAlgorithmException, CryptoKeyException, BadCryptException {
        String passphrase = "admin1234_+(((99*!2@@8*8)000=++++======~545";
        String iv = "--+simple_vector_passphrase++";

        String data = "Lorem ipsum dolor sit amet.";

        KeyGenerator keyGenerator = new KeyGenerator(KEY_SIZE);
        CryptoProvider cryptoProvider = new CryptoProvider(keyGenerator.createKey(passphrase));

        cryptoProvider.initializeVector(iv, IV_SIZE);

        byte[] encrypted = cryptoProvider.encrypt(data.getBytes());
        byte[] decrypted = cryptoProvider.decrypt(encrypted);

        assertTrue(Arrays.equals(decrypted, data.getBytes()), "Initial data and decrypted data are not equals");
    }
}
