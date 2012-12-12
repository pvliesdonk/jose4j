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
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import org.jose4j.keys.ExampleRsaKeyFromJws;
import org.jose4j.keys.ExampleEcKeysFromJws;
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
                "        \"n\": \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
                "   4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
                "   tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
                "   QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
                "   SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
                "   w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\",\n" +
                "        \"e\":\"AQAB\",\n" +
                "        \"kid\":\"2011-04-29\"}\n" +
                "     ]\n" +
                "   }";

        JsonWebKeySet jwkSet = new JsonWebKeySet(jwkJson);
        Collection<JsonWebKey> jwks = jwkSet.getJsonWebKeys();

        assertEquals(2, jwks.size());

        Iterator<JsonWebKey> iterator = jwks.iterator();
        assertTrue(iterator.next() instanceof EllipticCurveJsonWebKey);
        assertTrue(iterator.next() instanceof RsaJsonWebKey);

        JsonWebKey webKey1 = jwkSet.getKey("1");
        assertTrue(webKey1 instanceof EllipticCurveJsonWebKey);
        assertNotNull(webKey1.getPublicKey());
        JsonWebKey webKey2011 = jwkSet.getKey("2011-04-29");
        assertTrue(webKey2011 instanceof RsaJsonWebKey);
        assertNotNull(webKey2011.getPublicKey());

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
        assertTrue(jwk.getPublicKey() instanceof RSAPublicKey);
        assertEquals(RsaJsonWebKey.ALGORITHM_VALUE, jwk.getAlgorithm());
    }

    public void testFromEcPublicKeyAndBack() throws JoseException
    {

        for (ECPublicKey publicKey : new ECPublicKey[] {ExampleEcKeysFromJws.PUBLIC_256, ExampleEcKeysFromJws.PUBLIC_521})
        {
            EllipticCurveJsonWebKey webKey = new EllipticCurveJsonWebKey(publicKey);
            String kid = "kkiidd";
            webKey.setKeyId(kid);
            webKey.setUse(Use.ENCRYPTION);
            JsonWebKeySet jwkSet = new JsonWebKeySet(Collections.<JsonWebKey>singletonList(webKey));
            String json = jwkSet.toJson();

            assertTrue(json.contains(Use.ENCRYPTION));
            assertTrue(json.contains(kid));

            JsonWebKeySet parsedJwkSet = new JsonWebKeySet(json);
            Collection<JsonWebKey> webKeyKeyObjects = parsedJwkSet.getJsonWebKeys();
            assertEquals(1, webKeyKeyObjects.size());
            JsonWebKey jwk = parsedJwkSet.getKey(kid);
            assertEquals(EllipticCurveJsonWebKey.ALGORITHM_VALUE, jwk.getAlgorithm());
            assertEquals(kid, jwk.getKeyId());
            assertEquals(Use.ENCRYPTION, jwk.getUse());

            EllipticCurveJsonWebKey ecJsonWebKey = (EllipticCurveJsonWebKey) jwk;
            assertEquals(publicKey.getW().getAffineX(), ecJsonWebKey.getECPublicKey().getW().getAffineX());
            assertEquals(publicKey.getW().getAffineY(), ecJsonWebKey.getECPublicKey().getW().getAffineY());
            assertEquals(publicKey.getParams().getCofactor(), ecJsonWebKey.getECPublicKey().getParams().getCofactor());
            assertEquals(publicKey.getParams().getCurve(), ecJsonWebKey.getECPublicKey().getParams().getCurve());
            assertEquals(publicKey.getParams().getGenerator(), ecJsonWebKey.getECPublicKey().getParams().getGenerator());
            assertEquals(publicKey.getParams().getOrder(), ecJsonWebKey.getECPublicKey().getParams().getOrder());
        }
    }

    public void testFactoryWithEcPublicKey() throws JoseException
    {
        JsonWebKey jwk = JsonWebKey.Factory.newJwk(ExampleEcKeysFromJws.PUBLIC_256);
        assertTrue(jwk.getPublicKey() instanceof ECPublicKey);
        assertTrue(jwk instanceof EllipticCurveJsonWebKey);        
        assertEquals(EllipticCurveJsonWebKey.ALGORITHM_VALUE, jwk.getAlgorithm());
    }

    // todo think we need a test some place for "The array representation MUST not be shortened to omit
    // any leading zero bytes contained in the value." from jwk/jwa 'cause I'm pretty sure we are (or would be) shortening now
    
}
