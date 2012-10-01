package org.jose4j.jwe;

import org.jose4j.jwa.Algorithm;

/**
 */
public interface SymmetricEncryptionAlgorithm extends Algorithm
{
    int getKeySize();

    boolean isAead();

    Result encrypt(byte[] plaintext, byte[] key);

    public static class Result
    {
        private byte[] iv;
        private byte[] ciphertext;

        public byte[] getIv()
        {
            return iv;
        }

        public byte[] getCiphertext()
        {
            return ciphertext;
        }
    }
}