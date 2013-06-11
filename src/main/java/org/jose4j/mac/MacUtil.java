package org.jose4j.mac;

import org.jose4j.lang.UncheckedJoseException;

import javax.crypto.Mac;
import java.security.NoSuchAlgorithmException;

/**
 */
public class MacUtil
{
    public static final String HMAC_SHA256 = "HmacSHA256";
    public static final String HMAC_SHA384 = "HmacSHA384";
    public static final String HMAC_SHA512 = "HmacSHA512";

    public static Mac getMac(String algorithm)
    {
        Mac mac;

        try
        {
            mac = Mac.getInstance(algorithm);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new UncheckedJoseException("Unable to get a MAC implementation of algorithm name: " + algorithm, e);
        }

        return /* of the */ mac;
    }
}
