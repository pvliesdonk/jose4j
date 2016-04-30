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

package org.jose4j.json;

import org.junit.Assert;
import org.jose4j.lang.JoseException;
import org.junit.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

/**
 */
public class JsonUtilTest
{
    @Test
    public void needsEsc() throws Exception
    {
        // char array serialization wasn't escaping special characters like quote and backslash
        // and serialization of an unrecognized object was just getting the toString of it directly
        // both of which could result in invalid JSON. this tests that has been fixed
        Map<String, Object> map = new HashMap<>();
        map.put("char array", new char[]{'a', '\\', '\"'});
        map.put("some object", new Object());
        map.put("nested", Collections.singletonMap("chars", "\"meh".toCharArray()));
        map.put("nested also", Collections.singletonMap("obj", new Random()));

        String s = JsonUtil.toJson(map);
        System.out.println(s);
        Map<String, Object> parsedMap = JsonUtil.parseJson(s);
    }

    @Test
    public void testParseJson1() throws JoseException
    {
        String basic = "{\"key\":\"value\"}";
        Map<String,Object> map = JsonUtil.parseJson(basic);
        Assert.assertEquals(1, map.size());
        Assert.assertEquals("value", map.get("key"));
    }

    @Test
    public void testParseJsonDisallowDupes()
    {
        String basic = "{\"key\":\"value\",\"key\":\"value2\"}";

        try
        {
            Map<String,?> map = JsonUtil.parseJson(basic);
            Assert.fail("parsing of " + basic + " should fail because the same member name occurs multiple times but returned: " + map);
        }
        catch (JoseException e)
        {
            // expected
        }
    }

    @Test
    public void testParseJsonDisallowDupesMoreComplex()
    {
        String json = "{\n" +
                "  \"keys\": [\n" +
                "    {\n" +
                "      \"kty\": \"EC\",\n" +
                "      \"kid\": \"20b05\",\n" +
                "      \"use\": \"sig\",\n" +
                "      \"x\": \"baLYE[omitted]DLSIor7\",\n" +
                "      \"y\": \"Xh2Q4[omitted]AB3GKQ1\",\n" +
                "      \"crv\": \"P-384\"\n" +
                "    },\n" +
                "    {\n" +
                "      \"kty\": \"EC\",\n" +
                "      \"kid\": \"20b04\",\n" +
                "      \"use\": \"sig\",\n" +
                "      \"x\": \"-Pfjrs_rpNIu4XPMHOhW4DvhZ9sdEKgT8zINkLM6Yvg\",\n" +
                "      \"y\": \"1FXTX9JGWH4kG0KxUIQDqOIxC2R8w5sLHHYr6sjcTK4\",\n" +
                "      \"y\": \"1234567890abcdefghijklmnopqrstuvwxyzABCDEFG\",\n" +     // duplicate y
                "      \"crv\": \"P-256\"\n" +
                "    }\n" +
                "  ]\n" +
                "}";

        try
        {
            Map<String,?> map = JsonUtil.parseJson(json);
            Assert.fail("parsing of " + json + " should fail because the same member name occurs multiple times but returned: " + map);
        }
        catch (JoseException e)
        {
            // expected
        }
    }

    @Test
    public void testBiggerThanLong() throws Exception
    {
        String json = "{\"key\":\"value\",\"number\":90210, \"big number\":99990193716474719874987981237498321343555513331108571735145}";
        Map<String, Object> parsed = JsonUtil.parseJson(json);
        Assert.assertEquals(3, parsed.size());
    }



    //todo some general JSON tests?
    // todo disallow extra trailing data (and leading?)
}
