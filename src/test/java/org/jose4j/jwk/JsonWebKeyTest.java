package org.jose4j.jwk;

import junit.framework.TestCase;

import java.util.List;
import java.util.Iterator;
import java.util.Collections;

import org.jose4j.keys.ExampleRsaKeyFromJws;

/**
 */
public class JsonWebKeyTest extends TestCase
{
    public void testParseExample()
    {
        String jwkJson = "{\"keys\":\n" +
                "     [\n" +
                "       {\"alg\":\"EC\",\n" +
                "        \"crv\":\"P-256\",\n" +
                "        \"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\n" +
                "        \"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\n" +
                "        \"use\":\"enc\",\n" +
                "        \"kid\":\"1\"},\n" +
                "\n" +
                "       {\"alg\":\"RSA\",\n" +
                "        \"mod\": \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
                "   4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
                "   tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
                "   QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
                "   SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
                "   w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\",\n" +
                "        \"exp\":\"AQAB\",\n" +
                "        \"kid\":\"2011-04-29\"}\n" +
                "     ]\n" +
                "   }";

        JsonWebKeySet jwkSet = new JsonWebKeySet(jwkJson);
        List<JsonWebKey> jwks = jwkSet.getKeys();

        assertEquals(2, jwks.size());

        Iterator<JsonWebKey> iterator = jwks.iterator();
        assertTrue(iterator.next() instanceof EllipticCurveJsonWebKey);
        assertTrue(iterator.next() instanceof RsaJsonWebKey);

        assertTrue(jwkSet.getKey("1") instanceof EllipticCurveJsonWebKey);
        assertTrue(jwkSet.getKey("2011-04-29") instanceof RsaJsonWebKey);

        assertEquals(Use.ENCRYPTION, jwkSet.getKey("1").getUse());

        assertNull(jwkSet.getKey(null));
        assertNull(jwkSet.getKey("nope"));

        String json = jwkSet.toJson();
        assertNotNull(json);
        assertTrue(json.contains("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx"));
    }

    public void testFromRsaPublicKeyAndBack()
    {
        RsaJsonWebKey webKey = new RsaJsonWebKey(ExampleRsaKeyFromJws.PUBLIC_KEY);
        String kid = "my-key-id";
        webKey.setKeyId(kid);
        webKey.setUse(Use.SIGNATURE);
        JsonWebKeySet jwkSet = new JsonWebKeySet(Collections.<JsonWebKey>singletonList(webKey));
        String json = jwkSet.toJson();
        assertTrue(json.contains(Use.SIGNATURE));
        assertTrue(json.contains(kid));

        JsonWebKeySet parsedJwkSet = new JsonWebKeySet(json);
        List<JsonWebKey> webKeyKeyObjects = parsedJwkSet.getKeys();
        assertEquals(1, webKeyKeyObjects.size());
        JsonWebKey jwk = parsedJwkSet.getKey(kid);
        assertEquals(RsaJsonWebKey.ALGORITHM_VALUE, jwk.getAlgorithm());
        assertEquals(kid, jwk.getKeyId());
        assertEquals(Use.SIGNATURE, jwk.getUse());

        RsaJsonWebKey rsaJsonWebKey = (RsaJsonWebKey) jwk;
        assertEquals(ExampleRsaKeyFromJws.PUBLIC_KEY.getModulus(), rsaJsonWebKey.getRSAPublicKey().getModulus());
        assertEquals(ExampleRsaKeyFromJws.PUBLIC_KEY.getPublicExponent(), rsaJsonWebKey.getRSAPublicKey().getPublicExponent());
    }
}
