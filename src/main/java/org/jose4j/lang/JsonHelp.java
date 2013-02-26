package org.jose4j.lang;

import java.util.List;
import java.util.Map;

/**
 */
public class JsonHelp
{
    public static String getString(Map<String, Object> map, String name)
    {
        Object object = map.get(name);
        return (String) object;
    }

    public static List<String> getStringArray(Map<String, Object> map, String name)
    {
        Object object = map.get(name);
        return (List<String>) object;
    }


}
