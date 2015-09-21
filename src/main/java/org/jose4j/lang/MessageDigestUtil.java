package org.jose4j.lang;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 *
 */
public class MessageDigestUtil
{
    public static MessageDigest getMessageDigest(String alg)
    {
        try
        {
            return MessageDigest.getInstance(alg);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new UncheckedJoseException("Unable to get MessageDigest instance with " + alg);
        }
    }
}
