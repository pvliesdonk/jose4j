package org.jose4j.base64url;

import org.jose4j.base64url.internal.apache.commons.codec.binary.Base64;
import org.jose4j.base64url.internal.apache.commons.codec.binary.BaseNCodec;

/**
 *
 */
public class SimplePEMEncoder
{
    public static String encode(final byte[] bytes)
    {
        return getCodec().encodeToString(bytes);
    }

    public static byte[] decode(final String encoded)
    {
        return getCodec().decode(encoded);
    }

    static Base64 getCodec()
    {
        return new Base64(BaseNCodec.PEM_CHUNK_SIZE);
    }
}
