package org.jose4j.jwe.kdf;

import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.InvalidKeyException;
import org.jose4j.lang.StringUtil;
import org.jose4j.mac.MacUtil;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;

/**
 */
public class Pbkdf2JwkExampleTest
{
    @Test
    public void testThePbdkfPartFromJwkAppendixC() throws IOException, InvalidKeyException
    {
        // just the pbkdf2 part from http://tools.ietf.org/html/draft-ietf-jose-json-web-key-22#appendix-C

        String pass = "Thus from my lips, by yours, my sin is purged.";

        // The Salt value (UTF8(Alg) || 0x00 || Salt Input) is:
        byte[] saltValue = ByteUtil.convertUnsignedToSignedTwosComp(new int[]{80, 66, 69, 83, 50, 45, 72, 83, 50, 53, 54, 43, 65, 49, 50, 56, 75,
                87, 0, 217, 96, 147, 112, 150, 117, 70, 247, 127, 8, 155, 137, 174,
                42, 80, 215});

        int iterationCount = 4096;

        PasswordBasedKeyDerivationFunction2 pbkdf2 = new PasswordBasedKeyDerivationFunction2(MacUtil.HMAC_SHA256);
        byte[] derived = pbkdf2.derive(StringUtil.getBytesUtf8(pass), saltValue, iterationCount, 16);
        byte[] expectedDerived = ByteUtil.convertUnsignedToSignedTwosComp(new int[]{110, 171, 169, 92, 129, 92, 109, 117, 233, 242, 116, 233, 170, 14, 24, 75});
        Assert.assertArrayEquals(expectedDerived, derived);
    }
}
