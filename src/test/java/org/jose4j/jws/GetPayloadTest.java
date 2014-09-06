package org.jose4j.jws;

import org.jose4j.jwk.JsonWebKey;
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.JoseException;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

/**
 *
 */
public class GetPayloadTest
{
    @Test
    public void testGetPayloadVerifiedAndUnverifiedAndSysPropOverride() throws JoseException
    {
        JsonWebKey jwk = JsonWebKey.Factory.newJwk("{\"kty\":\"oct\",\"k\":\"Y7T0ygpIvYvz9kSVRod2tcGhekjiQh4t_AF7GE-v0o8\"}");
        String cs = "eyJhbGciOiJIUzI1NiJ9." +
                "VUExNTgyIHRvIFNGTyBmb3IgYSBOQVBQUyBGMkYgd29ya3Nob3AgaW4gUGFsbyBBbHRv." +
                "YjnCNkxrv86F6GufxddTYS_4URo3kmLKrREquZSEKDo";

        String propertyName = "org.jose4j.jws.getPayload-skip-verify";
        try
        {
            System.setProperty(propertyName, "true");
            JsonWebSignature jws = new JsonWebSignature();
            jws.setCompactSerialization(cs);
            String payload = jws.getPayload();
            assertNotNull(payload);
        }
        finally
        {
            System.clearProperty(propertyName);
        }

        try
        {
            JsonWebSignature jws = new JsonWebSignature();
            jws.setCompactSerialization(cs);
            String payload = jws.getPayload();
            fail("getPayload should have failed with no key set but did return: " + payload);
        }
        catch (JoseException e)
        {
            // expected
        }

        try
        {
            System.setProperty(propertyName, "true");
            JsonWebSignature jws = new JsonWebSignature();
            jws.setCompactSerialization(cs);
            jws.setKey(new HmacKey(new byte[32]));
            String payload = jws.getPayload();
            assertNotNull(payload);
        }
        finally
        {
            System.clearProperty(propertyName);
        }

        try
        {
            JsonWebSignature jws = new JsonWebSignature();
            jws.setCompactSerialization(cs);
            jws.setKey(new HmacKey(new byte[32]));
            String payload = jws.getPayload();
            fail("getPayload should have failed with wrong key set but did return: " + payload);
        }
        catch (JoseException e)
        {
            // expected
        }

        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(cs);
        String payload = jws.getUnverifiedPayload();
        assertNotNull(payload);
        jws.setKey(jwk.getKey());
    }
}
