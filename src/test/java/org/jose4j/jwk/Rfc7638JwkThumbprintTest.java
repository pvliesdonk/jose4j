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

package org.jose4j.jwk;

import org.jose4j.lang.JoseException;
import org.jose4j.lang.StringUtil;
import org.junit.Test;

import java.security.MessageDigest;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.jose4j.lang.HashUtil.*;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThat;

/**
 *
 */
public class Rfc7638JwkThumbprintTest
{
    @Test
    public void testRsaFromRfcExample3_1() throws JoseException
    {
        // http://tools.ietf.org/html/rfc7638#section-3.1
        String json = "     {\n" +
                "      \"kty\": \"RSA\",\n" +
                "      \"n\": \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt\n" +
                "            VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6\n" +
                "            4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD\n" +
                "            W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9\n" +
                "            1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH\n" +
                "            aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\",\n" +
                "      \"e\": \"AQAB\",\n" +
                "      \"alg\": \"RS256\",\n" +
                "      \"kid\": \"2011-04-29\"\n" +
                "     }";

        JsonWebKey jsonWebKey = JsonWebKey.Factory.newJwk(json);
        String actual = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";
        String calculated = jsonWebKey.calculateBase64urlEncodedThumbprint(SHA_256);
        assertThat(actual, equalTo(calculated));
    }

    @Test
    public void testOct() throws JoseException
    {
        String json = "{\"k\":\"ZW8Eg8TiwoT2YamLJfC2leYpLgLmUAh_PcMHqRzBnMg\",\"kty\":\"oct\"}";
        JsonWebKey jwk = JsonWebKey.Factory.newJwk(json);
        byte[] thumb = jwk.calculateThumbprint(SHA_256);

        MessageDigest messageDigest = getMessageDigest(SHA_256);
        byte[] digest = messageDigest.digest(StringUtil.getBytesUtf8(json));

        assertArrayEquals(digest, thumb);

        JsonWebKey jsonWebKey = JsonWebKey.Factory.newJwk("{\"kty\":\"oct\", \"k\":\"ZW8Eg8TiwoT2YamLJfC2leYpLgLmUAh_PcMHqRzBnMg\"}");

        assertThat(jwk.calculateBase64urlEncodedThumbprint(SHA_256), equalTo(jsonWebKey.calculateBase64urlEncodedThumbprint(SHA_256)));
    }

    @Test
    public void testEc() throws JoseException
    {
        String json = "{\"crv\":\"P-256\",\"kty\":\"EC\"," +
                "\"x\":\"CEuRLUISufhcjrj-32N0Bvl3KPMiHH9iSw4ohN9jxrA\"," +
                "\"y\":\"EldWz_iXSK3l_S7n4w_t3baxos7o9yqX0IjzG959vHc\"}";

        JsonWebKey jwk = JsonWebKey.Factory.newJwk(json);
        byte[] thumb = jwk.calculateThumbprint(SHA_256);

        MessageDigest messageDigest = getMessageDigest(SHA_256);
        byte[] digest = messageDigest.digest(StringUtil.getBytesUtf8(json));

        assertArrayEquals(digest, thumb);


        json = "{\"kty\":\"EC\"," +
                "\"y\":\"EldWz_iXSK3l_S7n4w_t3baxos7o9yqX0IjzG959vHc\"," +
                "\"crv\":\"P-256\"," +
                "\"x\":\"CEuRLUISufhcjrj-32N0Bvl3KPMiHH9iSw4ohN9jxrA\"}";

        jwk = JsonWebKey.Factory.newJwk(json);
        thumb = jwk.calculateThumbprint(SHA_256);

        assertArrayEquals(digest, thumb);
    }

    @Test
    public void testEcFromNimb() throws JoseException
    {
        String json = "{\"crv\":\"P-256\"," +
                " \"kty\":\"EC\"," +
                " \"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"," +
                " \"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\"}";
        JsonWebKey jwk = JsonWebKey.Factory.newJwk(json);
        String thumb = jwk.calculateBase64urlEncodedThumbprint(SHA_256);
        assertThat("cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s", equalTo(thumb));
    }

    @Test
    public void testOctFromNimb() throws JoseException
    {
        String json = "{\"kty\":\"oct\",\"k\":\"GawgguFyGrWKav7AX4VKUg\"}";
        JsonWebKey jwk = JsonWebKey.Factory.newJwk(json);
        String thumb = jwk.calculateBase64urlEncodedThumbprint(SHA_256);
        // looks like they have a bug in symmetric keys https://twitter.com/__b_c/status/645995173483147264
        // assertThat("mm1dkvdCX1bCNj9fNzdnZPUJ6fomGdWE52AjA2L8dA4", equalTo(thumb));
    }
}
