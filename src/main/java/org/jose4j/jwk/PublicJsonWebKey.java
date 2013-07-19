package org.jose4j.jwk;

import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.JsonHelp;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

/**
 */
public abstract class PublicJsonWebKey extends JsonWebKey
{
    protected PublicKey publicKey;
    protected boolean writeOutPrivateKeyToJson;
    protected PrivateKey privateKey;

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

    public void setWriteOutPrivateKeyToJson(boolean writeOutPrivateKeyToJson)
    {
        this.writeOutPrivateKeyToJson = writeOutPrivateKeyToJson;
    }

    public PrivateKey getPrivateKey()
    {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey)
    {
        this.privateKey = privateKey;
    }

    public static class Factory
    {
        public static PublicJsonWebKey newPublicJwk(Map<String,Object> params) throws JoseException
        {
            JsonWebKey jsonWebKey = JsonWebKey.Factory.newJwk(params);
            return (PublicJsonWebKey) jsonWebKey;
        }

        public static PublicJsonWebKey newPublicJwk(Key publicKey) throws JoseException
        {
            JsonWebKey jsonWebKey = JsonWebKey.Factory.newJwk(publicKey);
            return (PublicJsonWebKey) jsonWebKey;
        }

        public static PublicJsonWebKey newPublicJwk(String json) throws JoseException
        {
            Map<String, Object> parsed = JsonUtil.parseJson(json);
            return newPublicJwk(parsed);
        }
    }
}
