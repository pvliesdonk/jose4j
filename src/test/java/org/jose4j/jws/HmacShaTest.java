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
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.JoseException;

import java.security.Key;

/**
 *
 */
public class HmacShaTest extends TestCase
{
    Key KEY1 = new HmacKey(new byte[]{41, -99, 60, 91, 49, 70, -99, -14, -108, -81, 60, 37, 104, -116, 106, 104, -2, -95, 56, 103, 64, 10, -56, 120, 37, -48, 6, 9, 110, -96, 27, -4});
    Key KEY2 = new HmacKey(new byte[]{-67, 34, -45, 50, 13, 84, -79, 114, -16, -44, 26, -39, 4, -1, 26, 9, 38, 78, -107, 39, -81, 75, -18, 38, 56, 34, 13, 78, -73, 62, -60, 52});

    public void testHmacSha256A() throws JoseException
    {
        testBasicRoundTrip("some content that is the payload", AlgorithmIdentifiers.HMAC_SHA256);
    }

    public void testHmacSha256B() throws JoseException
    {
        testBasicRoundTrip("{\"iss\":\"https://jwt-idp.example.com\",\n" +
                "    \"prn\":\"mailto:mike@example.com\",\n" +
                "    \"aud\":\"https://jwt-rp.example.net\",\n" +
                "    \"iat\":1300815780,\n" +
                "    \"exp\":1300819380,\n" +
                "    \"http://claims.example.com/member\":true}", AlgorithmIdentifiers.HMAC_SHA256);
    }

    public void testHmacSha384A() throws JoseException
    {
        testBasicRoundTrip("Looking good, Billy Ray!", AlgorithmIdentifiers.HMAC_SHA384);
    }

    public void testHmacSha348B() throws JoseException
    {
        testBasicRoundTrip("{\"meh\":\"meh\"}", AlgorithmIdentifiers.HMAC_SHA384);
    }

    public void testHmacSha512A() throws JoseException
    {
        testBasicRoundTrip("Feeling good, Louis!", AlgorithmIdentifiers.HMAC_SHA512);
    }

    public void testHmacSha512B() throws JoseException
    {
        testBasicRoundTrip("{\"meh\":\"mehvalue\"}", AlgorithmIdentifiers.HMAC_SHA512);
    }

    void testBasicRoundTrip(String payload, String jwsAlgo) throws JoseException
    {
        JwsTestSupport.testBasicRoundTrip(payload, jwsAlgo, KEY1, KEY1, KEY2, KEY2);
    }


}
