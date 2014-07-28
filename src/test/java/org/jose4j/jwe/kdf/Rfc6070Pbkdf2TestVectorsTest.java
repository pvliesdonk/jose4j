package org.jose4j.jwe.kdf;

import org.apache.commons.codec.binary.Hex;
import org.jose4j.lang.StringUtil;
import org.junit.Assert;
import org.junit.Test;


/**
 * Tests from https://tools.ietf.org/html/rfc6070 which,
 * "contains test vectors for the Public-Key Cryptography
 *  Standards (PKCS) #5 Password-Based Key Derivation Function 2 (PBKDF2)
 *  with the Hash-based Message Authentication Code (HMAC) Secure Hash
 *  Algorithm (SHA-1) pseudorandom function."
 */
public class Rfc6070Pbkdf2TestVectorsTest
{
    @Test
    public void doRfc6070Test1() throws Exception
    {
        String p = "password";
        String s = "salt";
        int c = 1;
        int dkLen = 20;
        String expectedOutputInHex = "0c60c80f961f0e71f3a9b524af6012062fe037a6";
        testAndCompare(p, s, c, dkLen, expectedOutputInHex);
    }

    @Test
    public void doRfc6070Test2() throws Exception
    {
        String p = "password";
        String s = "salt";
        int c = 2;
        int dkLen = 20;
        String expectedOutputInHex = "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957";
        testAndCompare(p, s, c, dkLen, expectedOutputInHex);
    }

    @Test
    public void doRfc6070Test3() throws Exception
    {
        String p = "password";
        String s = "salt";
        int c = 4096;
        int dkLen = 20;
        String expectedOutputInHex = "4b007901b765489abead49d926f721d065a429c1";
        testAndCompare(p, s, c, dkLen, expectedOutputInHex);
    }

    //@Test  // this one takes too long to run b/c of the iteration count so don't run it normally
    public void doRfc6070Test4() throws Exception
    {
        String p = "password";
        String s = "salt";
        int c = 16777216;
        int dkLen = 20;
        String expectedOutputInHex = "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984";
        testAndCompare(p, s, c, dkLen, expectedOutputInHex);
    }

    @Test
    public void doRfc6070Test5() throws Exception
    {

        String p = "passwordPASSWORDpassword";
        String s = "saltSALTsaltSALTsaltSALTsaltSALTsalt";
        int c = 4096;
        int dkLen = 25;
        String expectedOutputInHex = "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038";
        testAndCompare(p, s, c, dkLen, expectedOutputInHex);
    }

    @Test
    public void doRfc6070Test6() throws Exception
    {
        String p = "pass\0word";
        String s = "sa\0lt";
        int c = 4096;
        int dkLen = 16;
        String expectedOutputInHex = "56fa6aa75548099dcc37d7f03425e0c3";
        testAndCompare(p, s, c, dkLen, expectedOutputInHex);
    }

    void testAndCompare(String p, String s, int c, int dkLen, String expectedOutputInHex) throws Exception
    {
        PasswordBasedKeyDerivationFunction2 pbkdf2 = new PasswordBasedKeyDerivationFunction2("HmacSHA1");
        byte[] derived = pbkdf2.derive(StringUtil.getBytesUtf8(p), StringUtil.getBytesUtf8(s), c, dkLen);
        byte[] expectedOutputInBytes = Hex.decodeHex(expectedOutputInHex.toCharArray());
        Assert.assertArrayEquals(expectedOutputInBytes, derived);
    }
}
