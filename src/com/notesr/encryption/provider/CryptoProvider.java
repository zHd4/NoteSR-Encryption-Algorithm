package com.notesr.encryption.provider;

import com.notesr.encryption.provider.exceptions.BadCryptException;
import com.notesr.encryption.provider.exceptions.CryptoKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

@SuppressWarnings("unused")
public class CryptoProvider {
    private byte[] iv;
    private final byte[] key;

    private int ivSize = 16;
    private int keySize = 128;

    public CryptoProvider() throws NoSuchAlgorithmException, CryptoKeyException {
        KeyGenerator keyGenerator = new KeyGenerator(keySize);
        this.key = keyGenerator.createKey();

        initializeVector(new String(Hash.randomSHA256Hash()));
    }

    public CryptoProvider(final int size) throws NoSuchAlgorithmException, CryptoKeyException {
        this.keySize = size;

        KeyGenerator keyGenerator = new KeyGenerator(keySize);
        this.key = keyGenerator.createKey();

        initializeVector(new String(Hash.randomSHA256Hash()));
    }

    public CryptoProvider(final byte[] key) throws NoSuchAlgorithmException, CryptoKeyException {
        this.keySize = key.length;
        this.key = key;

        initializeVector(new String(Hash.randomSHA256Hash()));
    }

    public byte[] encrypt(final byte[] raw) throws NoSuchAlgorithmException {
        Algorithm algorithm = new Algorithm(this.key);

        byte[] checkSum = Hash.sha256(raw);
        byte[] transformed = algorithm.transform(raw, Algorithm.ENCRYPTION_MODE);

        byte[] encrypted = Arrays.copyOf(transformed, transformed.length + checkSum.length);

        System.arraycopy(checkSum, 0, encrypted, transformed.length, checkSum.length);

        algorithm = new Algorithm(this.iv);
        encrypted = algorithm.transform(encrypted, Algorithm.ENCRYPTION_MODE);

        return encrypted;
    }

    public byte[] decrypt(final byte[] encrypted) throws NoSuchAlgorithmException, BadCryptException {
        Algorithm algorithm = new Algorithm(this.iv);

        int hashSize = Hash.randomSHA256Hash().length;

        byte[] transformed = algorithm.transform(encrypted, Algorithm.DECRYPTION_MODE);
        byte[] checkSum = new byte[hashSize];

        System.arraycopy(transformed, transformed.length - hashSize, checkSum, 0, hashSize);

        algorithm = new Algorithm(this.key);

        byte[] decrypted = algorithm.transform(
                Arrays.copyOf(transformed, transformed.length - hashSize), Algorithm.DECRYPTION_MODE);

        if(!Arrays.equals(checkSum, Hash.sha256(decrypted))) {
            throw new BadCryptException("Bad key or data");
        }

        return decrypted;
    }

    public void initializeVector(final String source) throws NoSuchAlgorithmException, CryptoKeyException {
        KeyGenerator keyGenerator = new KeyGenerator(ivSize);
        this.iv = keyGenerator.createKey(source);
    }

    public void initializeVector(final String source, final int size) throws NoSuchAlgorithmException, CryptoKeyException {
        this.ivSize = size;
        initializeVector(source);
    }
}
