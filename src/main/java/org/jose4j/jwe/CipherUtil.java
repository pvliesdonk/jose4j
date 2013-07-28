package org.jose4j.jwe;

import org.jose4j.lang.JoseException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;

/**
 */
public class CipherUtil
{
    static Cipher getCipher(String algorithm) throws JoseException
    {
        try
        {
            return Cipher.getInstance(algorithm);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new JoseException(e.toString() , e);
        }
        catch (NoSuchPaddingException e)
        {
            throw new JoseException(e.toString() , e);
        }
    }
}
