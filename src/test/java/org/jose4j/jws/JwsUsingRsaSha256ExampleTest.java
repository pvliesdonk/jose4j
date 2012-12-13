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
import org.jose4j.keys.ExampleRsaKeyFromJws;
import org.jose4j.lang.JoseException;

/**
 */
public class JwsUsingRsaSha256ExampleTest extends TestCase
{
    String JWS = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";

    public void testVerifyExample() throws JoseException
    {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(JWS);
        jws.setKey(ExampleRsaKeyFromJws.PUBLIC_KEY);
        assertTrue("signature should validate", jws.verifySignature());
    }

    public void testSignExample() throws JoseException
    {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload("{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}");
        jws.setHeaderAsString("{\"alg\":\"RS256\"}");
        jws.setKey(ExampleRsaKeyFromJws.PRIVATE_KEY);

        String compactSerialization = jws.getCompactSerialization();

        assertEquals("example jws value doesn't match calculated compact serialization", JWS, compactSerialization);
    }
}
