package org.jose4j.base64url;

/**
 *
 */
public class Base64
{
    public static String encode(final byte[] bytes)
    {
        return getCodec().encodeToString(bytes);
    }

    public static byte[] decode(final String encoded)
    {
        return getCodec().decode(encoded);
    }

    private static org.jose4j.base64url.internal.apache.commons.codec.binary.Base64 getCodec()
    {
        return new org.jose4j.base64url.internal.apache.commons.codec.binary.Base64();
    }
}
