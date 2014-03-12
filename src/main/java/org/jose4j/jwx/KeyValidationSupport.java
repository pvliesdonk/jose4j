package org.jose4j.jwx;

import org.jose4j.lang.InvalidKeyException;
import org.jose4j.lang.JoseException;

import java.security.Key;
import java.security.interfaces.RSAKey;

/**
 */
public class KeyValidationSupport
{
    public static final int MIN_RSA_KEY_LENGTH = 2048;

    public static void checkRsaKeySize(RSAKey rsaKey) throws InvalidKeyException
    {
        if (rsaKey == null)
        {
            throw new InvalidKeyException("The RSA key must not be null.");
        }

        int size = rsaKey.getModulus().bitLength();
        if  (size < MIN_RSA_KEY_LENGTH)
        {
           throw new InvalidKeyException("An RSA key of size "+MIN_RSA_KEY_LENGTH+
               " bits or larger MUST be used with the all JOSE RSA algorithms (given key was only "+size+ " bits).");
        }
    }

    public static <K extends Key> K castKey(Key key, Class<K> type) throws InvalidKeyException
    {
        notNull(key);

        try
        {
            return type.cast(key);
        }
        catch (ClassCastException e)
        {
            throw new InvalidKeyException("Invalid key " + e);
        }
    }

    public static void notNull(Key key) throws InvalidKeyException
    {
        if (key == null)
        {
            throw new InvalidKeyException("The key must not be null.");
        }
    }
}
