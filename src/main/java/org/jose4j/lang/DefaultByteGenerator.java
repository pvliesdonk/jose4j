package org.jose4j.lang;

import java.security.SecureRandom;
import java.util.Random;

/**
 */
public class DefaultByteGenerator implements ByteGenerator
{
    private final Random random;

    public DefaultByteGenerator()
    {
        this.random = new SecureRandom();
    }

    public byte[] randomBytes(int length)
    {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }
}
