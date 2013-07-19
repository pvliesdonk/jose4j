package org.jose4j.jwk;

import org.jose4j.keys.RsaKeyUtil;
import org.jose4j.lang.JoseException;

import java.security.KeyPair;

/**
 */
public class RsaJwkGenerator
{
    public static RsaJsonWebKey generateJwk(int bits) throws JoseException
    {
        RsaKeyUtil keyUtil = new RsaKeyUtil();
        KeyPair keyPair = keyUtil.generateKeyPair(bits);
        RsaJsonWebKey rsaJwk = (RsaJsonWebKey) PublicJsonWebKey.Factory.newPublicJwk(keyPair.getPublic());
        rsaJwk.setPrivateKey(keyPair.getPrivate());
        return rsaJwk;
    }
}
