/*
 * Copyright 2012-2015 Brian Campbell
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
package org.jose4j.jwt.consumer;

import org.apache.commons.logging.LogFactory;
import org.jose4j.http.Get;
import org.jose4j.http.Response;
import org.jose4j.http.SimpleResponse;
import org.jose4j.jwk.*;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.lang.UnresolvableKeyException;
import org.junit.Test;

import java.io.IOException;
import java.security.Key;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/**
 *
 */
public class HttpsJwksVerificationKeyResolverTest
{
    @Test
    public void simpleKeyFoundThenNotFoundAndRefreshToFindAndThenCantFind() throws Exception
    {
        String firstJkwsJson = "{\"keys\":[{\"kty\":\"EC\",\"kid\":\"k1\",\"x\":\"1u9oeAkLQJcAnrv_m4fupf-lF43yFqmNjMsrukKDhEE\",\"y\":\"RG0cyWzinUl8NpfVVw2DqfH6zRqU_yF6aL1swssNv4E\",\"crv\":\"P-256\"}]}";
        String secondJwkJson = "{\"keys\":[{\"kty\":\"EC\",\"kid\":\"k2\",\"x\":\"865vGRGnwRFf1YWFI-ODhHkQwYs7dc9VlI8zleEUqyA\",\"y\":\"W-7d1hvHrhNqNGVVNZjTUopIdaegL3jEjWOPX284AOk\",\"crv\":\"P-256\"}]}";

        JsonWebKeySet jwks = new JsonWebKeySet(firstJkwsJson);
        JsonWebKey k1 = jwks.getJsonWebKeys().iterator().next();

        jwks = new JsonWebKeySet(secondJwkJson);
        JsonWebKey k2 = jwks.getJsonWebKeys().iterator().next();

        String location = "https://www.example.org/";
        HttpsJwks httpsJkws = new HttpsJwks(location);

        Get mockGet = mock(Get.class);
        Map<String,List<String>> headers = Collections.emptyMap();
        SimpleResponse ok1 = new Response(200, "OK", headers, firstJkwsJson);
        SimpleResponse ok2 = new Response(200, "OK", headers, secondJwkJson);
        when(mockGet.get(location)).thenReturn(ok1, ok2);

        httpsJkws.setSimpleHttpGet(mockGet);

        HttpsJwksVerificationKeyResolver resolver = new HttpsJwksVerificationKeyResolver(httpsJkws);
        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        jws.setKeyIdHeaderValue("k1");
        Key key = resolver.resolveKey(jws, Collections.<JsonWebStructure>emptyList());
        assertThat(key, equalTo(k1.getKey()));

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        jws.setKeyIdHeaderValue("k1");
        key = resolver.resolveKey(jws, Collections.<JsonWebStructure>emptyList());
        assertThat(key, equalTo(k1.getKey()));

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        jws.setKeyIdHeaderValue("k1");
        key = resolver.resolveKey(jws, Collections.<JsonWebStructure>emptyList());
        assertThat(key, equalTo(k1.getKey()));

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        jws.setKeyIdHeaderValue("k2");
        key = resolver.resolveKey(jws, Collections.<JsonWebStructure>emptyList());
        assertThat(key, equalTo(k2.getKey()));

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        jws.setKeyIdHeaderValue("k2");
        key = resolver.resolveKey(jws, Collections.<JsonWebStructure>emptyList());
        assertThat(key, equalTo(k2.getKey()));

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        jws.setKeyIdHeaderValue("nope");
        try
        {
            key = resolver.resolveKey(jws, Collections.<JsonWebStructure>emptyList());
            fail("shouldn't have resolved a key but got " + key);
        }
        catch (UnresolvableKeyException e)
        {
            LogFactory.getLog(this.getClass()).debug("this was expected and is okay: " + e);
            assertFalse("do you really need UnresolvableKeyException inside a UnresolvableKeyException?", e.getCause() instanceof UnresolvableKeyException);
        }
    }

    @Test
    public void testAnEx() throws Exception
    {
        String location = "https://www.example.org/";

        Get mockGet = mock(Get.class);
        when(mockGet.get(location)).thenThrow(new IOException(location + "says 'no GET for you!'"));
        HttpsJwks httpsJkws = new HttpsJwks(location);
        httpsJkws.setSimpleHttpGet(mockGet);
        HttpsJwksVerificationKeyResolver resolver = new HttpsJwksVerificationKeyResolver(httpsJkws);

        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        jws.setKeyIdHeaderValue("nope");
        try
        {
            Key key = resolver.resolveKey(jws, Collections.<JsonWebStructure>emptyList());
            fail("shouldn't have resolved a key but got " + key);

        }
        catch (UnresolvableKeyException e)
        {
            LogFactory.getLog(this.getClass()).debug("this was expected and is okay: " + e);
        }
    }

}
