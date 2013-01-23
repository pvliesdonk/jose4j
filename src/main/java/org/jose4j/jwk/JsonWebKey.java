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

import org.jose4j.lang.JoseException;
import org.jose4j.json.JsonUtil;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.List;
import java.util.HashMap;

/**
 */
public abstract class JsonWebKey
{
    public static final String KEY_TYPE_MEMBER_NAME = "kty";
    public static final String USE_MEMBER_NAME = "use";
    public static final String KEY_ID_MEMBER_NAME = "kid";

    private String use;
    private String keyId;

    protected PublicKey publicKey;

    protected JsonWebKey(PublicKey publicKey)
    {
        this.publicKey = publicKey;
    }

    public JsonWebKey(Map<String, String> params)
    {
        use = params.get(USE_MEMBER_NAME);
        keyId = params.get(KEY_ID_MEMBER_NAME);
    }

    public abstract String getAlgorithm();
    protected abstract void fillTypeSpecificParams(Map<String,String> params);

    public String getUse()
    {
        return use;
    }

    public void setUse(String use)
    {
        this.use = use;
    }

    public String getKeyId()
    {
        return keyId;
    }

    public void setKeyId(String keyId)
    {
        this.keyId = keyId;
    }

    public PublicKey getPublicKey()
    {
        return publicKey;
    }

    public Map<String, String> toParams()
    {
        Map<String, String> params = new LinkedHashMap<String, String>();
        params.put(KEY_TYPE_MEMBER_NAME, getAlgorithm());
        putIfNotNull(USE_MEMBER_NAME, getUse(), params);
        putIfNotNull(KEY_ID_MEMBER_NAME, getKeyId(), params);
        fillTypeSpecificParams(params);
        return params;
    }

    public String toJson()
    {
        Map<String, String> params = toParams();
        return JsonUtil.toJson(params);
    }

    @Override
    public String toString()
    {
        return getClass().getName() + toParams();
    }

    protected void putIfNotNull(String name, String value, Map<String, String> params)
    {
        if (value != null)
        {
            params.put(name,value);
        }
    }

    public static class Factory
    {
        public static JsonWebKey newJwk(Map<String,String> params) throws JoseException
        {
            String alg = params.get(KEY_TYPE_MEMBER_NAME);

            if (RsaJsonWebKey.ALGORITHM_VALUE.equals(alg))
            {
                return new RsaJsonWebKey(params);
            }
            else if (EllipticCurveJsonWebKey.ALGORITHM_VALUE.equals(alg))
            {
                return new EllipticCurveJsonWebKey(params);
            }
            else
            {
                throw new JoseException("Unknown key algorithm: " + alg);
            }
        }

        public static JsonWebKey newJwk(PublicKey publicKey) throws JoseException
        {
            if (RSAPublicKey.class.isInstance(publicKey))
            {
                return new RsaJsonWebKey((RSAPublicKey)publicKey);
            }
            else if (ECPublicKey.class.isInstance(publicKey))
            {
                return new EllipticCurveJsonWebKey((ECPublicKey)publicKey);
            }
            else
            {
                throw new JoseException("Unsupported or unknown public key " + publicKey);
            }
        }

        public static JsonWebKey newJwk(String json) throws JoseException
        {
            Map<String, Object> parsed = JsonUtil.parseJson(json);
            Map<String, String> params = new HashMap<String,String>();
            for (Map.Entry<String,Object> e : parsed.entrySet())
            {
                if (String.class.isInstance(e.getValue()))
                {
                    params.put(e.getKey(), (String) e.getValue());
                }
            }
            return newJwk(params);
        }
    }
}
