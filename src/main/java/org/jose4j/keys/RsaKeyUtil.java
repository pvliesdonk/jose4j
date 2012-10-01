package org.jose4j.keys;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.math.BigInteger;

/**
 */
public class RsaKeyUtil
{
    private KeyFactory keyFactory;
    private static final String RSA = "RSA";

    public RsaKeyUtil()
    {
        try
        {
            keyFactory = KeyFactory.getInstance(RSA);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new IllegalStateException("Couldn't find "+ RSA + "KeyFactory!?!", e);
        }
    }

    public RSAPublicKey publicKey(BigInteger modulus, BigInteger publicExponent)
    {
        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
        try
        {
            PublicKey publicKey = keyFactory.generatePublic(rsaPublicKeySpec);
            return (RSAPublicKey) publicKey;
        }
        catch (InvalidKeySpecException e)
        {
            throw new IllegalArgumentException("Invalid key spec", e);
        }
    }

    public RSAPrivateKey privateKey(BigInteger modulus, BigInteger privateExponent)
    {
        RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(modulus, privateExponent);
        try
        {
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
            return (RSAPrivateKey) privateKey;
        }
        catch (InvalidKeySpecException e)
        {
            throw new IllegalArgumentException("Invalid key spec", e);
        }
    }
}
