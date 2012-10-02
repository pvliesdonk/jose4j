package org.jose4j.jwk;

import org.jose4j.json.JsonUtil;

import java.util.*;

/**
 */
public class JsonWebKeyContainer
{
    public static final String JWK_MEMBER_NAME = "jwk";

    private List<JsonWebKeyKeyObject> keys;

    public JsonWebKeyContainer(String json)
    {
        Map<String,Object> parsed = JsonUtil.parseJson(json);
        List<Map<String,String>> jwksList = (List<Map<String,String>>) parsed.get(JWK_MEMBER_NAME);

        keys = new ArrayList<JsonWebKeyKeyObject>(jwksList.size());
        for (Map<String,String> jwkParamsMap : jwksList)
        {
            keys.add(JsonWebKeyKeyObject.Factory.newJwk(jwkParamsMap));      
        }
    }

    public JsonWebKeyContainer(List<JsonWebKeyKeyObject> keys)
    {
        this.keys = keys;
    }

    public List<JsonWebKeyKeyObject> getKeys()
    {
        return keys;
    }

    public JsonWebKeyKeyObject getKey(String keyId)
    {
        if (keyId == null)
        {
            return null;
        }

        for (JsonWebKeyKeyObject key : keys)
        {
            if (keyId.equals(key.getKeyId()))
            {
                return key;
            }
        }

        return null;
    }

    public String toJson()
    {
        LinkedList<Map<String, String>> keyList = new LinkedList<Map<String, String>>();

        for (JsonWebKeyKeyObject key : keys)
        {
            keyList.add(key.toParams());
        }

        Map<String,Object> jwk = new LinkedHashMap<String,Object>();
        jwk.put(JWK_MEMBER_NAME, keyList);
        return JsonUtil.toJson(jwk);
    }
}
