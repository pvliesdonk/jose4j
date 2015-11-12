package org.jose4j.keys;

import javax.crypto.spec.SecretKeySpec;

/**
*
*/
public class FakeHsmNonExtractableSecretKeySpec extends SecretKeySpec
{
    public FakeHsmNonExtractableSecretKeySpec(byte[] data, String algorithm)
    {
        super(data, algorithm);
    }

    @Override
    public byte[] getEncoded()
    {
        return nullIt() ?  null : super.getEncoded();
    }

    @Override
    public String getFormat()
    {
        return nullIt() ? null : super.getFormat();
    }

    private boolean nullIt()
    {
        // to simulate a PKCS#11 situation where the key is non extractable and unavailable to the application layer
        StackTraceElement[] stackTrace = new Exception().getStackTrace();
        StackTraceElement stackTraceElement = stackTrace[2];
        return stackTraceElement.getClassName().startsWith("org.jose4j");
    }
}
