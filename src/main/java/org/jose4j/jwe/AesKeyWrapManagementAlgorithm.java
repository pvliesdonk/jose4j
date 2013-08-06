package org.jose4j.jwe;

import org.jose4j.keys.AesKey;
import org.jose4j.keys.KeyPersuasion;

/**
 */
public class AesKeyWrapManagementAlgorithm extends WrappingKeyManagementAlgorithm
{
    public AesKeyWrapManagementAlgorithm(String alg)
    {
        super("AESWrap", alg);
        setKeyType(AesKey.ALGORITHM);
        setKeyPersuasion(KeyPersuasion.SYMMETRIC);
    }
}
