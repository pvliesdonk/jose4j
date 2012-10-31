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

package org.jose4j.jws;

import junit.framework.TestCase;

import java.security.Key;

import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.JoseException;
import org.jose4j.keys.HmacKey;

/**
 */
public class JwsUsingHmacSha256ExampleTest extends TestCase
{
    String JWS = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    String PAYLOAD = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";
    

    int[]  KEY_UNSIGNED_BYTES = {3, 35, 53, 75, 43, 15, 165, 188, 131, 126, 6, 101, 119, 123, 166,
                       143, 90, 179, 40, 230, 240, 84, 201, 40, 169, 15, 132, 178, 210, 80,
                       46, 191, 211, 251, 90, 146, 210, 6, 71, 239, 150, 138, 180, 195, 119,
                       98, 61, 34, 61, 46, 33, 114, 5, 46, 79, 8, 192, 205, 154, 245, 103,
                       208, 128, 163};
    byte[] KEY_SIGNED_BYTES = ByteUtil.convertUnsignedToSignedTwosComp(KEY_UNSIGNED_BYTES);
    Key KEY = new HmacKey(KEY_SIGNED_BYTES);

    public void testVerifyExample() throws JoseException
    {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(JWS);
        Key key = KEY;
        jws.setKey(key);
        assertTrue("signature (HMAC) should validate", jws.verifySignature());
        assertEquals(PAYLOAD, jws.getPayload());
    }

    public void testSignExample() throws JoseException
    {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(PAYLOAD);

        jws.setKey(KEY);
        jws.setHeaderAsString("{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}");

        String compactSerialization = jws.getCompactSerialization();

        assertEquals("example jws value doesn't match calculated compact serialization", JWS, compactSerialization);
    }
}
