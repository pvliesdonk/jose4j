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
import org.jose4j.base64url.Base64Url;
import org.jose4j.keys.BigEndianBigInteger;
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.JoseException;

import java.security.Key;

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

    public void testKey11to12()
    {
        // draft 12 used a JWK encoding of the symmetric key where previously it was an octet sequence
        // and this is just a sanity check that it didn't change and my stuff sees them as the same
        // may want to redo some of this if/when symmetric key support gets added to this JWK impl
        String k = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";
        Base64Url base64Url = new Base64Url();
        String encodedKey = base64Url.base64UrlEncode(KEY_SIGNED_BYTES);
        assertEquals(k, encodedKey);
    }
}
