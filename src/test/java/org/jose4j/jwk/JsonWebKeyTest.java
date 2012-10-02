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
        String jwkJson = "{\"jwk\":\n" +
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

        JsonWebKeyContainer jwkContainer = new JsonWebKeyContainer(jwkJson);
        List<JsonWebKeyKeyObject> webKeyKeyObjects = jwkContainer.getKeys();

        assertEquals(2, webKeyKeyObjects.size());

        Iterator<JsonWebKeyKeyObject> iterator = webKeyKeyObjects.iterator();
        assertTrue(iterator.next() instanceof EllipticCurveJsonWebKey);
        assertTrue(iterator.next() instanceof RsaJsonWebKey);

        assertTrue(jwkContainer.getKey("1") instanceof EllipticCurveJsonWebKey);
        assertTrue(jwkContainer.getKey("2011-04-29") instanceof RsaJsonWebKey);

        assertEquals(Use.ENCRYPTION, jwkContainer.getKey("1").getUse());

        assertNull(jwkContainer.getKey(null));
        assertNull(jwkContainer.getKey("nope"));

        String json = jwkContainer.toJson();
        assertNotNull(json);
        assertTrue(json.contains("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx"));
    }

    public void testFromRsaPublicKeyAndBack()
    {
        RsaJsonWebKey webKey = new RsaJsonWebKey(ExampleRsaKeyFromJws.PUBLIC_KEY);
        String kid = "my-key-id";
        webKey.setKeyId(kid);
        webKey.setUse(Use.SIGNATURE);
        JsonWebKeyContainer jwkJsonWebKeyContainer = new JsonWebKeyContainer(Collections.<JsonWebKeyKeyObject>singletonList(webKey));
        String json = jwkJsonWebKeyContainer.toJson();
        assertTrue(json.contains(Use.SIGNATURE));
        assertTrue(json.contains(kid));

        JsonWebKeyContainer parsedContainer = new JsonWebKeyContainer(json);
        List<JsonWebKeyKeyObject> webKeyKeyObjects = parsedContainer.getKeys();
        assertEquals(1, webKeyKeyObjects.size());
        JsonWebKeyKeyObject keyObject = parsedContainer.getKey(kid);
        assertEquals(RsaJsonWebKey.ALGORITHM_VALUE, keyObject.getAlgorithm());
        assertEquals(kid, keyObject.getKeyId());
        assertEquals(Use.SIGNATURE, keyObject.getUse());

        RsaJsonWebKey rsaJsonWebKey = (RsaJsonWebKey) keyObject;
        assertEquals(ExampleRsaKeyFromJws.PUBLIC_KEY.getModulus(), rsaJsonWebKey.getRSAPublicKey().getModulus());
        assertEquals(ExampleRsaKeyFromJws.PUBLIC_KEY.getPublicExponent(), rsaJsonWebKey.getRSAPublicKey().getPublicExponent());
    }
}
