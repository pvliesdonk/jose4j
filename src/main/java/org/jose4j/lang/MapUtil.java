package org.jose4j.lang;

import java.util.Map;

/**
 */
public class MapUtil
{
    public static String getString(Map<String, Object> map, String name)
    {
        Object object = map.get(name);
        return (String) object;
    }

}
