package org.jose4j.jwk;

import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;

import java.util.Collection;
import java.util.List;

/**
 *
 */
public class VerificationJwkSelector
{
    public List<JsonWebKey> selectForVerify(JsonWebSignature jws, Collection<JsonWebKey> keys) throws JoseException
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
        return filter.filter(keys);

        // todo -> if zero or >1, try harder...
    }
}