package org.jose4j.jwk;

import java.util.Map;
import java.util.LinkedHashMap;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

/**
 */
public abstract class JsonWebKey
{
    public static final String ALGORITHM_MEMBER_NAME = "alg";
    public static final String USE_MEMBER_NAME = "use";
    public static final String KEY_ID_MEMBER_NAME = "kid";

    private String use;
    private String keyId;

    private PublicKey publicKey;

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
        params.put(ALGORITHM_MEMBER_NAME, getAlgorithm());
        putIfNotNull(USE_MEMBER_NAME, getUse(), params);
        putIfNotNull(KEY_ID_MEMBER_NAME, getKeyId(), params);
        fillTypeSpecificParams(params);
        return params;
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
        public static JsonWebKey newJwk(Map<String,String> params)
        {
            String alg = params.get(ALGORITHM_MEMBER_NAME);

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
                throw new IllegalArgumentException("Unknown key algorithm: " + alg);
            }
        }

        public static JsonWebKey newJwk(PublicKey publicKey)
        {
            if (RSAPublicKey.class.isInstance(publicKey))
            {
                return new RsaJsonWebKey((RSAPublicKey)publicKey);
            }
            else
            {
                throw new IllegalArgumentException("Unsupported public key " + publicKey);
            }
        }
    }
}
