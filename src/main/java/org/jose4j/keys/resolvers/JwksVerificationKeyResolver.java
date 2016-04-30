/*
 * Copyright 2012-2016 Brian Campbell
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
package org.jose4j.keys.resolvers;

import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.VerificationJwkSelector;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.UnresolvableKeyException;

import java.security.Key;
import java.util.List;

/**
 *
 */
public class JwksVerificationKeyResolver implements VerificationKeyResolver
{
    private List<JsonWebKey> jsonWebKeys;
    private VerificationJwkSelector selector = new VerificationJwkSelector();

    public JwksVerificationKeyResolver(List<JsonWebKey> jsonWebKeys)
    {
        this.jsonWebKeys = jsonWebKeys;
    }

    @Override
    public Key resolveKey(JsonWebSignature jws, List<JsonWebStructure> nestingContext) throws UnresolvableKeyException
    {
        JsonWebKey selected;
        try
        {
            selected = selector.select(jws, jsonWebKeys);
        }
        catch (JoseException e)
        {
            StringBuilder sb = new StringBuilder();
            sb.append("Unable to find a suitable verification key for JWS w/ header ").append(jws.getHeaders().getFullHeaderAsJsonString());
            sb.append(" due to an unexpected exception (").append(e).append(") selecting from keys: ").append(jsonWebKeys);
            throw new UnresolvableKeyException(sb.toString(), e);
        }

        if (selected == null)
        {
            StringBuilder sb = new StringBuilder();
            sb.append("Unable to find a suitable verification key for JWS w/ header ").append(jws.getHeaders().getFullHeaderAsJsonString());
            sb.append(" from JWKs ").append(jsonWebKeys);
            throw new UnresolvableKeyException(sb.toString());
        }

        return selected.getKey();
    }
}
