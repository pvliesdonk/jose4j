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

package org.jose4j.jwk;

import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;

import java.util.*;

/**
 */
public class JsonWebKeySet
{
    public static final String JWK_SET_MEMBER_NAME = "keys";

    private Collection<JsonWebKey> keys;

    public JsonWebKeySet(String json) throws JoseException
    {
        Map<String,Object> parsed = JsonUtil.parseJson(json);
        List<Map<String,String>> jwksList = (List<Map<String,String>>) parsed.get(JWK_SET_MEMBER_NAME);

        keys = new ArrayList<JsonWebKey>(jwksList.size());
        for (Map<String,String> jwkParamsMap : jwksList)
        {
            keys.add(JsonWebKey.Factory.newJwk(jwkParamsMap));
        }
    }

    public JsonWebKeySet(Collection<JsonWebKey> keys)
    {
        this.keys = keys;
    }

    public Collection<JsonWebKey> getJsonWebKeys()
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
