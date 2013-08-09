package org.jose4j.jwe;

import org.jose4j.keys.AesKey;
import org.jose4j.keys.KeyPersuasion;

/**
 */
public class AesKeyWrapManagementAlgorithm extends WrappingKeyManagementAlgorithm
{
    int keyByteLength;

    public AesKeyWrapManagementAlgorithm(String alg, int keyByteLength)
    {
        super("AESWrap", alg);
        setKeyType(AesKey.ALGORITHM);
        setKeyPersuasion(KeyPersuasion.SYMMETRIC);
        this.keyByteLength = keyByteLength;
    }

    int getKeyByteLength()
    {
        return keyByteLength;
    }
}
