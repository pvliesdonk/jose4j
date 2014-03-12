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
import org.jose4j.lang.JsonHelp;

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

    public void testParseJsonDisallowArrays()
    {
        String basic = "{\"key\": [\"value1\", \"val2\", \"etc.\"]}";

        try
        {
            Map<String,?> map = JsonHeaderUtil.parseJson(basic);
            fail("parsing of " + basic + " should fail because of array but returned: " + map);
        }
        catch (JoseException e)
        {
            // expected
        }
    }
}
