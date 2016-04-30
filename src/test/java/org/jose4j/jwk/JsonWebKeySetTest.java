/*
 * Copyright 2012-2016 Brian Campbell
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
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.keys.ExampleEcKeysFromJws;
import org.jose4j.keys.ExampleRsaKeyFromJws;
import org.jose4j.lang.JoseException;

import java.security.Key;
import java.security.interfaces.ECPublicKey;
import java.util.*;

/**
 */
public class JsonWebKeySetTest extends TestCase
{
    public void testParseExamplePublicKeys() throws JoseException
    {
        // from https://tools.ietf.org/html/draft-ietf-jose-json-web-key Appendix A.1
        String jwkJson = "{\"keys\":\n" +
                "     [\n" +
                "       {\"kty\":\"EC\",\n" +
                "        \"crv\":\"P-256\",\n" +
                "        \"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\n" +
                "        \"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\n" +
                "        \"use\":\"enc\",\n" +
                "        \"kid\":\"1\"},\n" +
                "\n" +
                "       {\"kty\":\"RSA\",\n" +
                "        \"n\": \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
                "   4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
                "   tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
                "   QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
                "   SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
                "   w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\",\n" +
                "        \"e\":\"AQAB\",\n" +
                "        \"alg\":\"RS256\",\n" +
                "        \"kid\":\"2011-04-29\"}\n" +
                "     ]\n" +
                "   }";

        JsonWebKeySet jwkSet = new JsonWebKeySet(jwkJson);
        Collection<JsonWebKey> jwks = jwkSet.getJsonWebKeys();

        assertEquals(2, jwks.size());

        Iterator<JsonWebKey> iterator = jwks.iterator();
        assertTrue(iterator.next() instanceof EllipticCurveJsonWebKey);
        assertTrue(iterator.next() instanceof RsaJsonWebKey);

        JsonWebKey webKey1 = jwkSet.findJsonWebKey("1", null, null, null);
        assertTrue(webKey1 instanceof EllipticCurveJsonWebKey);
        assertEquals(Use.ENCRYPTION, webKey1.getUse());
        assertNotNull(webKey1.getKey());
        assertNull(((PublicJsonWebKey) webKey1).getPrivateKey());
        JsonWebKey webKey2011 = jwkSet.findJsonWebKey("2011-04-29", null, null, null);
        assertTrue(webKey2011 instanceof RsaJsonWebKey);
        assertNotNull(webKey2011.getKey());
        assertNull(((PublicJsonWebKey) webKey2011).getPrivateKey());

        assertEquals(AlgorithmIdentifiers.RSA_USING_SHA256, webKey2011.getAlgorithm());

        assertEquals(Use.ENCRYPTION, jwkSet.findJsonWebKey("1", null, null, null).getUse());

        assertNull(jwkSet.findJsonWebKey("nope", null, null, null));

        String json = jwkSet.toJson();
        assertNotNull(json);
        assertTrue(json.contains("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx"));
    }

    public void testParseExamplePrivateKeys() throws JoseException
    {
        // from https://tools.ietf.org/html/draft-ietf-jose-json-web-key Appendix A.2
        String jwkJson = "{\"keys\":\n" +
                "       [\n" +
                "         {\"kty\":\"EC\",\n" +
                "          \"crv\":\"P-256\",\n" +
                "          \"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\n" +
                "          \"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\n" +
                "          \"d\":\"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE\",\n" +
                "          \"use\":\"enc\",\n" +
                "          \"kid\":\"1\"},\n" +
                "\n" +
                "         {\"kty\":\"RSA\",\n" +
                "          \"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4\n" +
                "     cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMst\n" +
                "     n64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2Q\n" +
                "     vzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbIS\n" +
                "     D08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw\n" +
                "     0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\",\n" +
                "          \"e\":\"AQAB\",\n" +
                "          \"d\":\"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9\n" +
                "     M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqij\n" +
                "     wp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d\n" +
                "     _cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBz\n" +
                "     nbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFz\n" +
                "     me1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q\",\n" +
                "          \"p\":\"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPV\n" +
                "     nwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqV\n" +
                "     WlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs\",\n" +
                "          \"q\":\"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyum\n" +
                "     qjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgx\n" +
                "     kIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk\",\n" +
                "          \"dp\":\"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oim\n" +
                "     YwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_Nmtu\n" +
                "     YZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0\",\n" +
                "          \"dq\":\"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUU\n" +
                "     vMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9\n" +
                "     GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk\",\n" +
                "          \"qi\":\"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzg\n" +
                "     UIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rx\n" +
                "     yR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\",\n" +
                "          \"alg\":\"RS256\",\n" +
                "          \"kid\":\"2011-04-29\"}\n" +
                "       ]\n" +
                "     }\n";

        JsonWebKeySet jwkSet = new JsonWebKeySet(jwkJson);
        Collection<JsonWebKey> jwks = jwkSet.getJsonWebKeys();

        assertEquals(2, jwks.size());

        Iterator<JsonWebKey> iterator = jwks.iterator();
        assertTrue(iterator.next() instanceof EllipticCurveJsonWebKey);
        assertTrue(iterator.next() instanceof RsaJsonWebKey);

        JsonWebKey webKey1 = jwkSet.findJsonWebKey("1", null, null, null);
        assertTrue(webKey1 instanceof EllipticCurveJsonWebKey);
        assertEquals(Use.ENCRYPTION, webKey1.getUse());
        assertNotNull(webKey1.getKey());
        assertNotNull(((PublicJsonWebKey) webKey1).getPrivateKey());
        JsonWebKey webKey2011 = jwkSet.findJsonWebKey("2011-04-29", null, null, null);
        assertTrue(webKey2011 instanceof RsaJsonWebKey);
        assertNotNull(webKey2011.getKey());
        assertEquals(AlgorithmIdentifiers.RSA_USING_SHA256, webKey2011.getAlgorithm());
        assertNotNull(((PublicJsonWebKey) webKey2011).getPrivateKey());

        assertEquals(Use.ENCRYPTION, jwkSet.findJsonWebKey("1", null, null, null).getUse());

        assertNull(jwkSet.findJsonWebKey("nope", null, null, null));

        String json = jwkSet.toJson();
        assertNotNull(json);
        assertTrue(json.contains("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx"));
    }

    public void testParseExampleSymmetricKeys() throws JoseException
    {
        // from https://tools.ietf.org/html/draft-ietf-jose-json-web-key Appendix A.3
        String jwkJson = "{\"keys\":\n" +
                "       [\n" +
                "         {\"kty\":\"oct\",\n" +
                "          \"alg\":\"A128KW\",\n" +
                "          \"k\":\"GawgguFyGrWKav7AX4VKUg\"},\n" +
                "\n" +
                "         {\"kty\":\"oct\",\n" +
                "          \"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75\n" +
                "     aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\",\n" +
                "          \"kid\":\"HMAC key used in JWS A.1 example\"}\n" +
                "       ]\n" +
                "     }\n";

        JsonWebKeySet jwkSet = new JsonWebKeySet(jwkJson);
        Collection<JsonWebKey> jwks = jwkSet.getJsonWebKeys();

        assertEquals(2, jwks.size());

        Iterator<JsonWebKey> iterator = jwks.iterator();
        assertTrue(iterator.next() instanceof OctetSequenceJsonWebKey);
        assertTrue(iterator.next() instanceof OctetSequenceJsonWebKey);
        assertFalse(iterator.hasNext());

        JsonWebKey jwk2 = jwkSet.findJsonWebKey("HMAC key used in JWS A.1 example", null, null, null);
        Key key2 = jwk2.getKey();
        assertNotNull(key2);
        assertEquals(64, key2.getEncoded().length);

        JsonWebKey jwk1 = jwkSet.findJsonWebKey(null, null, null, KeyManagementAlgorithmIdentifiers.A128KW);
        Key key1 = jwk1.getKey();
        assertNotNull(key1);
        assertEquals(16, key1.getEncoded().length);

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
        JsonWebKey jwk = parsedJwkSet.findJsonWebKey(kid, null, null, null);
        assertEquals(RsaJsonWebKey.KEY_TYPE, jwk.getKeyType());
        assertEquals(kid, jwk.getKeyId());
        assertEquals(Use.SIGNATURE, jwk.getUse());

        RsaJsonWebKey rsaJsonWebKey = (RsaJsonWebKey) jwk;
        assertEquals(ExampleRsaKeyFromJws.PUBLIC_KEY.getModulus(), rsaJsonWebKey.getRsaPublicKey().getModulus());
        assertEquals(ExampleRsaKeyFromJws.PUBLIC_KEY.getPublicExponent(), rsaJsonWebKey.getRsaPublicKey().getPublicExponent());
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
            JsonWebKey jwk = parsedJwkSet.findJsonWebKey(kid, null, null, null);
            assertEquals(EllipticCurveJsonWebKey.KEY_TYPE, jwk.getKeyType());
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

    public void testCreateFromListOfPubJwks() throws JoseException
    {
        List<PublicJsonWebKey> ecjwks = new ArrayList<>();
        ecjwks.add(EcJwkGenerator.generateJwk(EllipticCurves.P256));
        ecjwks.add(EcJwkGenerator.generateJwk(EllipticCurves.P256));
        JsonWebKeySet jsonWebKeySet = new JsonWebKeySet(ecjwks);
        assertEquals(2, jsonWebKeySet.getJsonWebKeys().size());
    }

    public void testOctAndDefaultToJson() throws JoseException
    {
        JsonWebKeySet jwks = new JsonWebKeySet(OctJwkGenerator.generateJwk(128), OctJwkGenerator.generateJwk(128));
        String json = jwks.toJson();
        assertTrue(json.contains("\"k\""));

        JsonWebKeySet newJwks = new JsonWebKeySet(json);
        assertEquals(jwks.getJsonWebKeys().size(), newJwks.getJsonWebKeys().size());
    }

    public void testNewWithVarArgsAndAddLater() throws Exception
    {
        JsonWebKey jwk1 = JsonWebKey.Factory.newJwk("{\"kty\":\"oct\",\"k\":\"bbj4v-CvqwOm1q3WkVJEpw\"}");
        JsonWebKey jwk2 = JsonWebKey.Factory.newJwk("{\"kty\":\"oct\",\"k\":\"h008v_ab_Z-N7q13D-JabC\"}");
        JsonWebKey jwk3 = JsonWebKey.Factory.newJwk("{\"kty\":\"oct\",\"k\":\"-_-8888888888888888-_-\"}");
        JsonWebKey jwk4 = JsonWebKey.Factory.newJwk("{\"kty\":\"oct\",\"k\":\"__--_12_--33--_21_--__\"}");

        JsonWebKeySet jwks = new JsonWebKeySet(jwk1);
        jwks.addJsonWebKey(jwk2);
        List<JsonWebKey> jwkList = jwks.getJsonWebKeys();
        jwkList.add(jwk3);

        assertEquals(3, jwkList.size());
        assertEquals(3, jwks.getJsonWebKeys().size());

        jwks = new JsonWebKeySet(jwkList);
        jwks.addJsonWebKey(jwk4);

        assertEquals(4, jwks.getJsonWebKeys().size());
    }


}
