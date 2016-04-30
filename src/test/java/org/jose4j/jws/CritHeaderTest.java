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
package org.jose4j.jws;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.keys.ExampleEcKeysFromJws;
import org.jose4j.lang.JoseException;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

/**
 *
 */
public class CritHeaderTest
{
    private static final Logger log = LoggerFactory.getLogger(JwsTestSupport.class);

    @Test
    public void testOnNewKey() throws Exception
    {
        final String headerName = "urn:example.com:nope";

        final String[] compactSerializations = {"eyJhbGciOiJFUzI1NiIsImNyaXQiOlsidXJuOmV4YW1wbGUuY29tOm5vcGUiXX0." +
                "aG93IGNyaXRpY2FsIHJlYWxseT8." +
                "F-xgvRuuaqawpLAiq6ArALlPB0Ay5_EU0YSPtw4U9teq82Gv1GyNzpO51V-u35p_oCe9dT-h0HxeznIg-uMxpQ",
                "eyJhbGciOiJFUzI1NiIsImNyaXQiOlsidXJuOmV4YW1wbGUuY29tOm5vcGUiXSwidXJuOmV4YW1wbGUuY29tOm5vcGUiOiJodWgifQ" +
                ".aG93IGNyaXRpY2FsIHJlYWxseT8." +
                "xZvf_WCSZY2-oMvpTbHALCGgOchR8ryrV_84Q5toM8KECtm9PCEuORoMKHmCFx-UTOI1QNt28H51GV9MB4c6BQ"};

        for (String cs : compactSerializations)
        {
            JsonWebSignature jws = new JsonWebSignature();
            jws.setCompactSerialization(cs);
            jws.setKey(ExampleEcKeysFromJws.PUBLIC_256);

            expectFail(jws);

            jws = new JsonWebSignature();
            jws.setCompactSerialization(cs);
            jws.setKey(ExampleEcKeysFromJws.PUBLIC_256);
            jws.setKnownCriticalHeaders(headerName);
            assertThat("how critical really?", equalTo(jws.getPayload()));
        }
    }

    public static void expectFail(JsonWebStructure jwx)
    {
        try
        {
            jwx.getPayload();
            fail("should have failed due to crit header");
        }
        catch (JoseException e)
        {
            log.debug("Expected something like this: {}", e.toString());
        }
    }

    @Test
    public void testJwsAppendixE() throws JoseException
    {
        // http://tools.ietf.org/html/rfc7515#appendix-E
        String jwscs = "eyJhbGciOiJub25lIiwNCiAiY3JpdCI6WyJodHRwOi8vZXhhbXBsZS5jb20vVU5ERU" +
                "ZJTkVEIl0sDQogImh0dHA6Ly9leGFtcGxlLmNvbS9VTkRFRklORUQiOnRydWUNCn0." +
                "RkFJTA.";
        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(jwscs);
        jws.setAlgorithmConstraints(AlgorithmConstraints.ALLOW_ONLY_NONE);

        expectFail(jws);

        jws = new JsonWebSignature();
        jws.setCompactSerialization(jwscs);
        jws.setAlgorithmConstraints(AlgorithmConstraints.ALLOW_ONLY_NONE);
        jws.setKnownCriticalHeaders("http://example.com/UNDEFINED"); // -> in the actual encoded example even thought the text says http://example.invalid/UNDEFINED
        assertThat(jws.getPayload(), equalTo("FAIL"));
    }

    @Test
    public void testJwsBadCrit() throws JoseException
    {
        final String[] compactSerializations =
        {
            "eyJhbGciOiJub25lIiwKICJjcml0Ijoic2hvdWxkbm90d29yayIKfQ.RkFJTA.",
            "eyJhbGciOiJub25lIiwKICJjcml0Ijp0cnVlCn0.bWVo."
        };

        for (String cs : compactSerializations)
        {
            JsonWebSignature jws = new JsonWebSignature();
            jws.setCompactSerialization(cs);
            jws.setAlgorithmConstraints(AlgorithmConstraints.ALLOW_ONLY_NONE);

            expectFail(jws);
        }
    }

    @Test
    public void simpleRoundTrip() throws JoseException
    {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setKey(ExampleEcKeysFromJws.PRIVATE_256);
        final String payload = "This family is in a rut. We gotta shake things up. We're driving to Walley World.";
        jws.setPayload(payload);
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        jws.setCriticalHeaderNames("nope");
        final String jwsCompactSerialization = jws.getCompactSerialization();

        jws = new JsonWebSignature();
        jws.setCompactSerialization(jwsCompactSerialization);
        jws.setKey(ExampleEcKeysFromJws.PUBLIC_256);

        expectFail(jws);

        jws = new JsonWebSignature();
        jws.setCompactSerialization(jwsCompactSerialization);
        jws.setKey(ExampleEcKeysFromJws.PUBLIC_256);
        jws.setKnownCriticalHeaders("nope");
        assertThat(jws.getPayload(), equalTo(payload));
    }
}
