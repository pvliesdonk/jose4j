package org.jose4j.keys;

import junit.framework.TestCase;

import java.math.BigInteger;
import java.util.Arrays;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.DecoderException;

/**
 */
public class BigEndianBigIntegerTest extends TestCase
{
    public void testExampleStuff()
    {
        basicConversionTest(BigEndianBigInteger.toBase64Url(ExampleRsaKeyFromJws.PUBLIC_KEY.getPublicExponent()));
        basicConversionTest(BigEndianBigInteger.toBase64Url(ExampleRsaKeyFromJws.PUBLIC_KEY.getModulus()));
        basicConversionTest(BigEndianBigInteger.toBase64Url(ExampleRsaKeyFromJws.PRIVATE_KEY.getPrivateExponent()));
    }

    public void testBasicConversions()
    {
        for (int i = 0; i < 500; i++)
        {
            basicConversionTest(i);
        }
    }

    public void testBasicConversions2()
    {
        for (long l = 200; l < Long.MAX_VALUE && l > 0; l=l*2)
        {
            for (int i = -100; i <= 100; i++)
            {
                basicConversionTest(l+i);
            }
        }
    }

    public void testBasicConversionSub0()
    {
        try
        {
            basicConversionTest(-1);
            fail("negitive numbers shouldn't work");
        }
        catch (IllegalArgumentException e)
        {
        }
    }

    public void testBasicConversionSub0MinLong()
    {
        try
        {
            basicConversionTest(Long.MIN_VALUE);
            fail("negitive numbers shouldn't work");
        }
        catch (IllegalArgumentException e)
        {
        }
    }

    public void testBasicConversion0()
    {
        basicConversionTest(0);
    }

    public void testBasicConversion1()
    {
        basicConversionTest(129);
    }

    public void testBasicConversion2()
    {
        basicConversionTest(8388608);
    }

    public void testBasicConversion3()
    {
        basicConversionTest(8388609);
    }

    public void testBasicConversion4()
    {
        basicConversionTest(8388811);
    }

    public void testBasicConversion5()
    {
        basicConversionTest(16777215);
    }
    
    public void testBasicConversion6()
    {
        basicConversionTest(16777217);
    }

    public void testBasicConversionMaxLong()
    {
        basicConversionTest(Long.MAX_VALUE);
    }

    private void basicConversionTest(long i)
    {
        BigInteger bigInt1 = BigInteger.valueOf(i);
        String b64 = BigEndianBigInteger.toBase64Url(bigInt1);
        BigInteger bigInt2= BigEndianBigInteger.fromBase64Url(b64);
        assertEquals(bigInt1, bigInt2);

        byte[] bytes = BigEndianBigInteger.toByteArray(bigInt1);
        byte[] bytes2 = toByteArrayViaHex(bigInt1);
        boolean okay = Arrays.equals(bytes, bytes2);
        assertTrue("array comp on " + i + " " + Arrays.toString(bytes) + " " + Arrays.toString(bytes2), okay);
    }

    public void testConversion1()
    {
        basicConversionTest("AQAB");
    }

    public void testConversion2()
    {
        basicConversionTest("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4");
    }

    public void testConversion3()
    {
        basicConversionTest("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM");
    }

    public void testConversion4()
    {
        String s = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
                "4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
                "tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
                "QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
                "SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
                "w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
        basicConversionTest(s);
    }

    private void basicConversionTest(String urlEncodedBytes)
    {
        BigInteger bigInt = BigEndianBigInteger.fromBase64Url(urlEncodedBytes);
        String b64 = BigEndianBigInteger.toBase64Url(bigInt);
        assertEquals(urlEncodedBytes, b64);
        BigInteger bigInt2 = BigEndianBigInteger.fromBase64Url(b64);
        assertEquals(bigInt, bigInt2);

        byte[] bytes = BigEndianBigInteger.toByteArray(bigInt);
        byte[] bytes2 = toByteArrayViaHex(bigInt);
        assertTrue("array comp on " + urlEncodedBytes, Arrays.equals(bytes, bytes2));
    }

    private byte[] toByteArrayViaHex(BigInteger bigInteger)
    {
        try
        {
            // ugly but a sanity check
            String hexString = bigInteger.toString(16);
            if (hexString.length() % 2 != 0)
            {
                hexString = "0" + hexString;
            }
            return Hex.decodeHex(hexString.toCharArray());
        }
        catch (DecoderException e)
        {
            throw new IllegalArgumentException("Problem converting BigInteger to byte array via hex.", e);
        }
    }
}
