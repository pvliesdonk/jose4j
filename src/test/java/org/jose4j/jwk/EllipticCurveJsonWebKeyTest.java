package org.jose4j.jwk;

import junit.framework.TestCase;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.keys.ExampleEcKeysFromJws;
import org.jose4j.lang.JoseException;

/**
 */
public class EllipticCurveJsonWebKeyTest extends TestCase
{
    public void testParseExampleWithPrivate256() throws JoseException
    {
        // key from http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-13#appendix-A.3.1
        // it was shown as octets in -11 and before
        String jwkJson = "{\"kty\":\"EC\",\n" +
                   " \"crv\":\"P-256\",\n" +
                   " \"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\n" +
                   " \"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\",\n" +
                   " \"d\":\"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI\"\n" +
                   "}";
        JsonWebKey jwk = JsonWebKey.Factory.newJwk(jwkJson);
        PublicJsonWebKey pubJwk = (PublicJsonWebKey) jwk;
        assertEquals(ExampleEcKeysFromJws.PRIVATE_256, pubJwk.getPrivateKey());
        assertEquals(ExampleEcKeysFromJws.PUBLIC_256, pubJwk.getPublicKey());
        assertEquals(EllipticCurves.P_256, ((EllipticCurveJsonWebKey)jwk).getCurveName());
    }

    public void testFromKeyWithPrivate256() throws JoseException
    {
        PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(ExampleEcKeysFromJws.PUBLIC_256);
        assertEquals(EllipticCurves.P_256, ((EllipticCurveJsonWebKey)jwk).getCurveName());
        String jsonNoPrivateKey = jwk.toJson();
        jwk.setPrivateKey(ExampleEcKeysFromJws.PRIVATE_256);
        String d = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI";
        assertFalse(jwk.toJson().contains(d));
        assertEquals(jsonNoPrivateKey, jwk.toJson());

        jwk.setWriteOutPrivateKeyToJson(true);
        assertTrue(jwk.toJson().contains(d));
    }

    public void testParseExampleWithPrivate512() throws JoseException
    {
        // this key also from http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-13#appendix-A.3.1
        // it was shown as octets in -11 and before
        String jwkJson = "{\"kty\":\"EC\",\n" +
                " \"crv\":\"P-521\",\n" +
                " \"x\":\"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_\n" +
                "      NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk\",\n" +
                " \"y\":\"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDl\n" +
                "      y79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2\",\n" +
                " \"d\":\"AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPA\n" +
                "      xerEzgdRhajnu0ferB0d53vM9mE15j2C\"\n" +
                "}";
        JsonWebKey jwk = JsonWebKey.Factory.newJwk(jwkJson);
        PublicJsonWebKey pubJwk = (PublicJsonWebKey) jwk;
        assertEquals(ExampleEcKeysFromJws.PRIVATE_521, pubJwk.getPrivateKey());
        assertEquals(ExampleEcKeysFromJws.PUBLIC_521, pubJwk.getPublicKey());
        assertEquals(EllipticCurves.P_521, ((EllipticCurveJsonWebKey)jwk).getCurveName());
    }

    public void testFromKeyWithPrivate512() throws JoseException
    {
        PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(ExampleEcKeysFromJws.PUBLIC_521);
        assertEquals(EllipticCurves.P_521, ((EllipticCurveJsonWebKey)jwk).getCurveName());
        String jsonNoPrivateKey = jwk.toJson();
        jwk.setPrivateKey(ExampleEcKeysFromJws.PRIVATE_521);
        String d = "AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C";
        assertFalse(jwk.toJson().contains(d));
        assertEquals(jsonNoPrivateKey, jwk.toJson());

        jwk.setWriteOutPrivateKeyToJson(true);
        assertTrue(jwk.toJson().contains(d));
    }
}
