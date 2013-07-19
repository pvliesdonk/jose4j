package org.jose4j.jwk;

import org.jose4j.keys.EcKeyUtil;
import org.jose4j.lang.JoseException;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.ECParameterSpec;

/**
 */
public class EcJwkGenerator
{
    public static EllipticCurveJsonWebKey generateJwk(ECParameterSpec spec) throws JoseException
    {
        EcKeyUtil keyUtil = new EcKeyUtil();
        KeyPair keyPair = keyUtil.generateKeyPair(spec);
        PublicKey publicKey = keyPair.getPublic();
        EllipticCurveJsonWebKey ecJwk = (EllipticCurveJsonWebKey) PublicJsonWebKey.Factory.newPublicJwk(publicKey);
        ecJwk.setPrivateKey(keyPair.getPrivate());
        return ecJwk;
    }
}
