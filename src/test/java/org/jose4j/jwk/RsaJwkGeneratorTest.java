package org.jose4j.jwk;

import junit.framework.TestCase;

/**
 */
public class RsaJwkGeneratorTest extends TestCase
{
    public void testGenerateJwk() throws Exception
    {
        RsaJsonWebKey rsaJsonWebKey = RsaJwkGenerator.generateJwk(2048);
        assertNotNull(rsaJsonWebKey.getPrivateKey());
        assertNotNull(rsaJsonWebKey.getPublicKey());
        assertNotNull(rsaJsonWebKey.getKey());
    }
}
