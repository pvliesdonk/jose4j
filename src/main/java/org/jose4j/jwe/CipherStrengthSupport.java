package org.jose4j.jwe;

import org.jose4j.lang.ByteUtil;

import javax.crypto.Cipher;
import java.security.NoSuchAlgorithmException;

/**
 */
public class CipherStrengthSupport
{
    public static boolean isAvailable(String algorithm, int keyByteLength)
    {
        int bitKeyLength = ByteUtil.bitLength(keyByteLength);
        try
        {
            int maxAllowedKeyLength = Cipher.getMaxAllowedKeyLength(algorithm);
            return (bitKeyLength <= maxAllowedKeyLength);
        }
        catch (NoSuchAlgorithmException e)
        {
            return false;
        }
    }

}
