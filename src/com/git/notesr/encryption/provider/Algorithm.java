package com.git.notesr.encryption.provider;

class Algorithm {
    private final byte[] key;

    public static final int ENCRYPTION_MODE = 0;
    public static final int DECRYPTION_MODE = 1;

    Algorithm(byte[] key) {
        this.key = key;
    }

    public byte[] transform(byte[] data, int mode) {
        int keyIndex = 0;
        byte[] transformed = new byte[data.length];

        for(int i = 0; i < data.length; i++) {
            transformed[i] = (byte) (data[i] + (
                    mode == ENCRYPTION_MODE ?  key[keyIndex] : -key[keyIndex]
            ));

            keyIndex = keyIndex == key.length - 1 ? 0 : keyIndex + 1;
        }

        return transformed;
    }
}
