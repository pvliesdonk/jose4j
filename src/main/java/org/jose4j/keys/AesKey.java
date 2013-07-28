package org.jose4j.keys;

import javax.crypto.spec.SecretKeySpec;

/**
 */
public class AesKey extends SecretKeySpec
{
    public static final String ALGORITHM = "AES";

    public AesKey(byte[] bytes)
    {
        super(bytes, ALGORITHM);
    }
}
