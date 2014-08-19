/*
 * Copyright 2012-2013 Brian Campbell
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

import junit.framework.TestCase;
import org.jose4j.lang.JoseException;

import java.util.Map;

/**
 */
public class JsonHeaderUtilTest extends TestCase
{
    public void testParseJson1() throws JoseException
    {
        String basic = "{\"key\":\"value\"}";
        Map<String,Object> map = JsonHeaderUtil.parseJson(basic);
        assertEquals(1, map.size());
        assertEquals("value", map.get("key"));
    }

    public void testParseJsonDisallowDupes()
    {
        String basic = "{\"key\":\"value\",\"key\":\"value2\"}";

        try
        {
            Map<String,?> map = JsonHeaderUtil.parseJson(basic);
            fail("parsing of " + basic + " should fail because the same member name occurs multiple times but returned: " + map);
        }
        catch (JoseException e)
        {
            // expected
        }
    }

    public void testParseJsonDisallowDupesMoreComplex()
    {
        String json = "{\n" +
                "  \"keys\": [\n" +
                "    {\n" +
                "      \"kty\": \"EC\",\n" +
                "      \"kid\": \"20b06\",\n" +
                "      \"use\": \"sig\",\n" +
                "      \"x\": \"AXN9jWp9rpUE6XMxH3tsOZMbFRL-7beDHVCzWaZL-zUeHBaV48-oqRr0pnN7K6iyywqlYXCeqgDUsldpOcSCBB4A\",\n" +
                "      \"y\": \"hKyRVd_GbKG7BIyoM09ZKtNDVJOtQTSZ9CX4wEqMDF1vXXFzrhEMsvB5E234gmMWBdKAnJW3-7NTTAFGmh39OXU\",\n" +
                "      \"crv\": \"P-521\"\n" +
                "    },\n" +
                "    {\n" +
                "      \"kty\": \"EC\",\n" +
                "      \"kid\": \"20b05\",\n" +
                "      \"use\": \"sig\",\n" +
                "      \"x\": \"baLYEBtgwuj7YjAx6bhZ1nM_gZu8TgQQ8h6gNQ9IIiPNkxCOV-QDLjLcQ0USIor7\",\n" +
                "      \"y\": \"Xh2QpnzdA9gz4aMaHDhSNl-MXeET54bylNZMkSqy1gDW17uhOH8FZBL6AB3GKQA1\",\n" +
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
                "    },\n" +
                "    {\n" +
                "      \"kty\": \"EC\",\n" +
                "      \"kid\": \"20b02\",\n" +
                "      \"use\": \"sig\",\n" +
                "      \"x\": \"AaQZH0dX7tgq4nRq-f6LwlryxdTgEY0JTFoLwWZkgfQl0tD0uFhHAGhgR_c6bba4thZUIuvMDW-IIiilFb9ZfXQd\",\n" +
                "      \"y\": \"AdDIPzaV4vagVlY-pXxhEmFuKJ171U-R0Wad2z-1yw_Ks2jWGYtqNr2B3qr-5N8xyBViplgKBfmB5BvBa2i-tVT6\",\n" +
                "      \"crv\": \"P-521\"\n" +
                "    }\n" +
                "  ]\n" +
                "}";

        try
        {
            Map<String,?> map = JsonHeaderUtil.parseJson(json);
            fail("parsing of " + json + " should fail because the same member name occurs multiple times but returned: " + map);
        }
        catch (JoseException e)
        {
            // expected
        }
    }
}
