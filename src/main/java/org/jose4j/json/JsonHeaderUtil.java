package org.jose4j.json;

import org.json.simple.JSONValue;
import org.json.simple.parser.ContainerFactory;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 */
public class JsonHeaderUtil
{
    private static final ContainerFactory CONTAINER_FACTORY = new ContainerFactory()
    {
        public List creatArrayContainer()
        {
            throw new IllegalArgumentException("Headers should not contain json array entries.");
        }

        public Map createObjectContainer()
        {
            return new DupeKeyDisallowingLinkedHashMap();
        }
    };

    public static Map<String,String> parseJson(String jsonString)
    {
        try
        {
            JSONParser parser = new JSONParser();
            return (DupeKeyDisallowingLinkedHashMap)parser.parse(jsonString, CONTAINER_FACTORY);
        }
        catch (ParseException e)
        {
            throw new IllegalArgumentException("Parsing error.", e);
        }
    }

    public static String toJson(Map<String,String> map)
    {
        return JSONValue.toJSONString(map);
    }

    static class DupeKeyDisallowingLinkedHashMap extends LinkedHashMap<String,String>
    {
        @Override
        public String put(String key, String value)
        {
            if (this.containsKey(key))
            {
                throw new IllegalArgumentException("An entry for '" + key + "' already exists.");
            }
            
            return super.put(key, value); 
        }
    }
}
