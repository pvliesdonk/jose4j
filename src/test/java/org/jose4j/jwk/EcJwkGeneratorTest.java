package org.jose4j.jwk;

import junit.framework.TestCase;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.lang.JoseException;

import java.security.spec.ECParameterSpec;

/**
 */
public class EcJwkGeneratorTest extends TestCase
{
    public void testGen() throws JoseException
    {
        for (ECParameterSpec spec : new ECParameterSpec[]{EllipticCurves.P256, EllipticCurves.P384, EllipticCurves.P521})
        {
            EllipticCurveJsonWebKey ecJwk = EcJwkGenerator.generateJwk(spec);
            assertNotNull(ecJwk.getKey());
            assertNotNull(ecJwk.getPublicKey());
            assertNotNull(ecJwk.getPrivateKey());
        }
    }
}
