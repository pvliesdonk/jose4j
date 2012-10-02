package org.jose4j.jwk;

import org.jose4j.json.JsonUtil;

import java.util.*;

/**
 */
public class JsonWebKeySet
{
    public static final String JWK_SET_MEMBER_NAME = "keys";

    private List<JsonWebKey> keys;

    public JsonWebKeySet(String json)
    {
        Map<String,Object> parsed = JsonUtil.parseJson(json);
        List<Map<String,String>> jwksList = (List<Map<String,String>>) parsed.get(JWK_SET_MEMBER_NAME);

        keys = new ArrayList<JsonWebKey>(jwksList.size());
        for (Map<String,String> jwkParamsMap : jwksList)
        {
            keys.add(JsonWebKey.Factory.newJwk(jwkParamsMap));
        }
    }

    public JsonWebKeySet(List<JsonWebKey> keys)
    {
        this.keys = keys;
    }

    public List<JsonWebKey> getKeys()
    {
        return keys;
    }

    public JsonWebKey getKey(String keyId)
    {
        if (keyId == null)
        {
            return null;
        }

        for (JsonWebKey key : keys)
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

        for (JsonWebKey key : keys)
        {
            keyList.add(key.toParams());
        }

        Map<String,Object> jwk = new LinkedHashMap<String,Object>();
        jwk.put(JWK_SET_MEMBER_NAME, keyList);
        return JsonUtil.toJson(jwk);
    }
}