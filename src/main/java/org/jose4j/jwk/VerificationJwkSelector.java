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
        SimpleJwkFilter filter = new SimpleJwkFilter();
        String kid = jws.getKeyIdHeaderValue();
        if (kid != null)
        {
            filter.setKid(kid, SimpleJwkFilter.VALUE_REQUIRED);
        }

        String x5t = jws.getX509CertSha1ThumbprintHeaderValue();
        String x5tS256 = jws.getX509CertSha256ThumbprintHeaderValue();
        filter.setAllowFallbackDeriveFromX5cForX5Thumbs(true);
        if (x5t != null)
        {
            filter.setX5t(x5t, SimpleJwkFilter.OMITTED_OKAY);
        }
        if (x5tS256 != null)
        {
            filter.setX5tS256(x5tS256, SimpleJwkFilter.OMITTED_OKAY);
        }

        String keyType = jws.getKeyType();
        filter.setKty(keyType);
        filter.setUse(Use.SIGNATURE, SimpleJwkFilter.OMITTED_OKAY);
        List<JsonWebKey> filtered = filter.filter(keys);

        if (hasMoreThanOne(filtered))
        {
            filter.setAlg(jws.getAlgorithmHeaderValue(), SimpleJwkFilter.OMITTED_OKAY);
            filtered = filter.filter(filtered);
        }

        if (hasMoreThanOne(filtered) && EllipticCurveJsonWebKey.KEY_TYPE.equals(keyType))
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