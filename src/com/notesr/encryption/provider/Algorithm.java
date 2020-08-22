package com.notesr.encryption.provider;

class Algorithm {
    private final byte[] key;

    public static final int ENCRYPTION_MODE = 0;
    public static final int DECRYPTION_MODE = 1;

    Algorithm(byte[] key) {
        this.key = key;
    }

    public byte[] transform(final byte[] data, final int mode) {
        int keyIndex = 0;

        for(int i = 0; i < data.length; i++) {
            data[i] = (byte) (mode == ENCRYPTION_MODE ? data[i] + key[keyIndex] : data[i] - key[keyIndex]);
            keyIndex = keyIndex == key.length - 1 ? 0 : keyIndex + 1;
        }

        return data;
    }
}
