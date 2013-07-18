package org.jose4j.jwk;

import java.security.PublicKey;
import java.util.Map;

/**
 */
public abstract class PublicJsonWebKey extends JsonWebKey
{
    protected PublicKey publicKey;

    // todo x5c etc, fun

    protected PublicJsonWebKey(PublicKey publicKey)
    {
        super(publicKey);
        this.publicKey = publicKey;
    }

    protected PublicJsonWebKey(Map<String, Object> params)
    {
        super(params);
    }

    public PublicKey getPublicKey()
    {
        return publicKey;
    }
}
