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
package org.jose4j.jwk;

import org.jose4j.jws.EcdsaUsingShaAlgorithm;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jws.JsonWebSignatureAlgorithm;
import org.jose4j.lang.JoseException;

import java.util.Collection;
import java.util.List;

/**
 *
 */
public class VerificationJwkSelector
{
    public JsonWebKey select(JsonWebSignature jws, Collection<JsonWebKey> keys) throws JoseException
    {
        List<JsonWebKey> jsonWebKeys = selectList(jws, keys);
        return jsonWebKeys.isEmpty() ? null : jsonWebKeys.get(0);
    }

    public List<JsonWebKey> selectList(JsonWebSignature jws, Collection<JsonWebKey> keys) throws JoseException
    {
        SimpleJwkFilter filter = SelectorSupport.commonFilterForInbound(jws);
        List<JsonWebKey> filtered = filter.filter(keys);

        if (hasMoreThanOne(filtered))
        {
            filter.setAlg(jws.getAlgorithmHeaderValue(), SimpleJwkFilter.OMITTED_OKAY);
            filtered = filter.filter(filtered);
        }

        if (hasMoreThanOne(filtered) && EllipticCurveJsonWebKey.KEY_TYPE.equals(jws.getKeyType()))
        {
            JsonWebSignatureAlgorithm algorithm = jws.getAlgorithm();
            EcdsaUsingShaAlgorithm ecdsaAlgorithm = (EcdsaUsingShaAlgorithm) algorithm;
            filter.setCrv(ecdsaAlgorithm.getCurveName(), SimpleJwkFilter.OMITTED_OKAY);
            filtered = filter.filter(filtered);
        }

        return filtered;

        // todo -> if >1, try even harder... maybe. But are there actually realistic cases where this will happen?
    }

    private boolean hasMoreThanOne(List<JsonWebKey> filtered)
    {
        return filtered.size() > 1;
    }
}