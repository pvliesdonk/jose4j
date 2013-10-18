package org.jose4j.jwx;

import org.jose4j.lang.JoseException;

import java.security.Key;
import java.security.interfaces.RSAKey;

/**
 */
public class KeyValidationSupport
{
    public static final int MIN_RSA_KEY_LENGTH = 2048;

    public static void checkRsaKeySize(RSAKey rsaKey) throws JoseException
    {
        if (rsaKey == null)
        {
            throw new JoseException("The RSA key must not be null.");
        }

        int size = rsaKey.getModulus().bitLength();
        if  (size < MIN_RSA_KEY_LENGTH)
        {
           throw new JoseException("An RSA key of size "+MIN_RSA_KEY_LENGTH+
               " bits or larger MUST be used with the all JOSE RSA algorithms (given key was only "+size+ " bits).");
        }
    }

    public static <K extends Key> K castKey(Key key, Class<K> type) throws JoseException
    {
        if (key == null)
        {
            throw new JoseException("The key must not be null.");
        }

        try
        {
            return type.cast(key);
        }
        catch (ClassCastException e)
        {
            throw new JoseException("Invalid key " + e);
        }
    }
}
