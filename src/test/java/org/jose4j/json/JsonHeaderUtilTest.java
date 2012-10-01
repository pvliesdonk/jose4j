package org.jose4j.json;

import junit.framework.TestCase;

import java.util.Map;

/**
 */
public class JsonHeaderUtilTest extends TestCase
{
    public void testParseJson1()
    {
        String basic = "{\"key\":\"value\"}";
        Map<String,String> map = JsonHeaderUtil.parseJson(basic);
        assertEquals(1, map.size());
        assertEquals("value", map.get("key"));
    }

    public void testParseJsonDisallowDupes()
    {
        String basic = "{\"key\":\"value\",\"key\":\"value2\"}";

        try
        {
            Map<String,String> map = JsonHeaderUtil.parseJson(basic);
            fail("parsing of " + basic + " should fail because the same member name occurs multiple times but returned: " + map);
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    public void testParseJsonDisallowArrays()
    {
        String basic = "{\"key\": [\"value1\", \"val2\", \"etc.\"]}";

        try
        {
            Map<String,String> map = JsonHeaderUtil.parseJson(basic);
            fail("parsing of " + basic + " should fail because of array but returned: " + map);
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

}
