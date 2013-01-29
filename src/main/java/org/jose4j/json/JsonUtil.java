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

package org.jose4j.json;

import org.jose4j.lang.JoseException;
import org.json.simple.JSONValue;
import org.json.simple.parser.ContainerFactory;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.io.IOException;
import java.io.Writer;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

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

    public static Map<String,Object> parseJson(String jsonString) throws JoseException
    {
        try
        {
            JSONParser parser = new JSONParser();
            return (Map<String,Object>)parser.parse(jsonString, CONTAINER_FACTORY);
        }
        catch (ParseException e)
        {
            throw new JoseException("Parsing error: " + e, e);
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
