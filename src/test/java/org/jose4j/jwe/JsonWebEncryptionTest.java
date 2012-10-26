package org.jose4j.jwe;

import junit.framework.TestCase;
import org.jose4j.keys.ExampleRsaKeyFromJws;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.lang.JoseException;

/**
 */
public class JsonWebEncryptionTest extends TestCase
{
    public void testTesting() throws JoseException
    {
        String plaintext = "{\"plain\":\"text\",\"a key\":\"with some value\",\"some:claim\":true}";
        JsonWebEncryption jwe = new JsonWebEncryption();        
        jwe.setPlaintext(plaintext);
        jwe.setAlgorithmHeaderValue(KeyEncryptionAlgorithmIdentifiers.RSA1_5);
        jwe.setKey(ExampleRsaKeyFromJws.PUBLIC_KEY);
        jwe.setHeader(HeaderParameterNames.ENCRYPTION_METHOD, SymmetricEncryptionAlgorithmIdentifiers.A128CBC);

        String jweCompactSerialization = jwe.getCompactSerialization();
    }
}
