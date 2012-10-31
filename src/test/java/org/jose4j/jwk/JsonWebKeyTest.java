/*
 * Copyright 2012 Brian Campbell
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jose4j.jwk;

import junit.framework.TestCase;

import java.util.Iterator;
import java.util.Collections;
import java.util.Collection;

import org.jose4j.keys.ExampleRsaKeyFromJws;
import org.jose4j.lang.JoseException;

/**
 */
public class JsonWebKeyTest extends TestCase
{
    public void testParseExample() throws JoseException
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
        Collection<JsonWebKey> jwks = jwkSet.getJsonWebKeys();

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

    public void testFromRsaPublicKeyAndBack() throws JoseException
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
        Collection<JsonWebKey> webKeyKeyObjects = parsedJwkSet.getJsonWebKeys();
        assertEquals(1, webKeyKeyObjects.size());
        JsonWebKey jwk = parsedJwkSet.getKey(kid);
        assertEquals(RsaJsonWebKey.ALGORITHM_VALUE, jwk.getAlgorithm());
        assertEquals(kid, jwk.getKeyId());
        assertEquals(Use.SIGNATURE, jwk.getUse());

        RsaJsonWebKey rsaJsonWebKey = (RsaJsonWebKey) jwk;
        assertEquals(ExampleRsaKeyFromJws.PUBLIC_KEY.getModulus(), rsaJsonWebKey.getRSAPublicKey().getModulus());
        assertEquals(ExampleRsaKeyFromJws.PUBLIC_KEY.getPublicExponent(), rsaJsonWebKey.getRSAPublicKey().getPublicExponent());
    }

    public void testFactoryWithRsaPublicKey() throws JoseException
    {
        JsonWebKey jwk = JsonWebKey.Factory.newJwk(ExampleRsaKeyFromJws.PUBLIC_KEY);
        assertTrue(jwk instanceof RsaJsonWebKey);
        assertEquals(RsaJsonWebKey.ALGORITHM_VALUE, jwk.getAlgorithm());
    }
}
