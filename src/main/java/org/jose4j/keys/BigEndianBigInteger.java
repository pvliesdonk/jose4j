package org.jose4j.keys;

import org.jose4j.base64url.Base64Url;
import java.math.BigInteger;

/**
 */
public class BigEndianBigInteger
{
    public static BigInteger fromBytes(byte[] magnitude)
    {
        return new BigInteger(1, magnitude);
    }

    public static BigInteger fromBase64Url(String base64urlEncodedBytes)
    {
        Base64Url base64Url = new Base64Url();
        byte[] magnitude = base64Url.base64UrlDecode(base64urlEncodedBytes);
        return fromBytes(magnitude);
    }

    public static byte[] toByteArray(BigInteger bigInteger)
    {
        if (bigInteger.signum() < 0)
        {
            String msg = "Cannot convert negative values to an unsigned magnitude byte array: " + bigInteger;
            throw new IllegalArgumentException(msg);
        }

        byte[] twosComplementBytes = bigInteger.toByteArray();
        byte[] magnitude;

        if ((bigInteger.bitLength() % 8 == 0) && (twosComplementBytes[0] == 0) && twosComplementBytes.length > 1)
        {
            byte[] bytes = new byte[twosComplementBytes.length - 1];
            System.arraycopy(twosComplementBytes, 1, bytes, 0, bytes.length);
            magnitude = bytes;
        }
        else
        {
            magnitude = twosComplementBytes;
        }

        return magnitude;
    }

    public static String toBase64Url(BigInteger bigInteger)
    {
        Base64Url base64Url = new Base64Url();
        byte[] bytes = toByteArray(bigInteger);
        return base64Url.base64UrlEncode(bytes);
    }
}
