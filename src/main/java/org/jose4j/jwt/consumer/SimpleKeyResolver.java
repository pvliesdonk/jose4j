package org.jose4j.jwt.consumer;

import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.JsonWebStructure;

import java.security.Key;
import java.util.List;

/**
 *
 */
class SimpleKeyResolver implements VerificationKeyResolver, DecryptionKeyResolver
{
    private Key key;

    SimpleKeyResolver(Key key)
    {
        this.key = key;
    }

    @Override
    public Key resolveKey(JsonWebEncryption jwe, List<JsonWebStructure> nestingContext)
    {
        return key;
    }

    @Override
    public Key resolveKey(JsonWebSignature jws, List<JsonWebStructure> nestingContext)
    {
        return key;
    }
}
