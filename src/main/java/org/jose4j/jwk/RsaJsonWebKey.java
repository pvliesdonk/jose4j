package org.jose4j.jwk;

import org.jose4j.keys.BigEndianBigInteger;
import org.jose4j.keys.RsaKeyUtil;

import java.util.Map;
import java.security.interfaces.RSAPublicKey;
import java.math.BigInteger;

/**
 */
public class RsaJsonWebKey extends JsonWebKey
{
    public static final String MODULUS_MEMBER_NAME = "mod";
    public static final String EXPONENT_MEMBER_NAME = "exp";

    public static final String ALGORITHM_VALUE = "RSA";

    private RSAPublicKey publicKey;

    public RsaJsonWebKey(RSAPublicKey publicKey)
    {
        super(publicKey);
        this.publicKey = publicKey;
    }

    public RsaJsonWebKey(Map<String, String> params)
    {
        super(params);
        String b64Modulus = params.get(MODULUS_MEMBER_NAME);
        BigInteger modulus = BigEndianBigInteger.fromBase64Url(b64Modulus);

        String b64Exponent = params.get(EXPONENT_MEMBER_NAME);
        BigInteger publicExponent = BigEndianBigInteger.fromBase64Url(b64Exponent);

        RsaKeyUtil rsaKeyUtil = new RsaKeyUtil();
        publicKey = rsaKeyUtil.publicKey(modulus, publicExponent);
    }

    public String getAlgorithm()
    {
        return ALGORITHM_VALUE;
    }

    public RSAPublicKey getRSAPublicKey()
    {
        return publicKey;
    }

    protected void fillTypeSpecificParams(Map<String, String> params)
    {
        BigInteger modulus = publicKey.getModulus();
        String b64Modulus = BigEndianBigInteger.toBase64Url(modulus);
        params.put(MODULUS_MEMBER_NAME, b64Modulus);

        BigInteger publicExponent = publicKey.getPublicExponent();
        String b64Exponent = BigEndianBigInteger.toBase64Url(publicExponent);
        params.put(EXPONENT_MEMBER_NAME, b64Exponent);
    }
}
