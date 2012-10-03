package org.jose4j.json;

import org.json.simple.parser.ContainerFactory;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.json.simple.JSONValue;

import java.util.Map;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.io.Writer;
import java.io.IOException;

/**
 */
public class JsonUtil
{
    private static final ContainerFactory CONTAINER_FACTORY = new ContainerFactory()
    {
        public List creatArrayContainer()
        {
            return new LinkedList<Object>();
        }

        public Map createObjectContainer()
        {
            return new LinkedHashMap<String,Object>();
        }
    };

    public static Map<String,Object> parseJson(String jsonString)
    {
        try
        {
            JSONParser parser = new JSONParser();
            return (Map<String,Object>)parser.parse(jsonString, CONTAINER_FACTORY);
        }
        catch (ParseException e)
        {
            throw new IllegalArgumentException("Parsing error.", e);
        }
    }

    public static String toJson(Map<String,?> map)
    {
        return JSONValue.toJSONString(map);
    }

    public static void writeJson(Map<String,?> map, Writer w) throws IOException
    {
        JSONValue.writeJSONString(map, w);
    }
}
