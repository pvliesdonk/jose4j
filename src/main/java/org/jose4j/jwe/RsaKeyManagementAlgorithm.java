package org.jose4j.jwe;

import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwx.KeyValidationSupport;
import org.jose4j.keys.KeyPersuasion;
import org.jose4j.lang.JoseException;

import java.security.Key;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 */
public class RsaKeyManagementAlgorithm extends WrappingKeyManagementAlgorithm implements KeyManagementAlgorithm
{
    public RsaKeyManagementAlgorithm(String javaAlg, String alg)
    {
        super(javaAlg, alg);
        setKeyType(RsaJsonWebKey.KEY_TYPE);
        setKeyPersuasion(KeyPersuasion.ASYMMETRIC);
    }

    @Override
    public void validateEncryptionKey(Key managementKey, ContentEncryptionAlgorithm contentEncryptionAlg) throws JoseException
    {
        RSAPublicKey rsaPublicKey = KeyValidationSupport.castKey(managementKey, RSAPublicKey.class);
        KeyValidationSupport.checkRsaKeySize(rsaPublicKey);
    }

    @Override
    public void validateDecryptionKey(Key managementKey, ContentEncryptionAlgorithm contentEncryptionAlg) throws JoseException
    {
        RSAPrivateKey rsaPrivateKey = KeyValidationSupport.castKey(managementKey, RSAPrivateKey.class);
        KeyValidationSupport.checkRsaKeySize(rsaPrivateKey);
    }

    @Override
    public boolean isAvailable()
    {
        return true; // todo maybe check about RSA though it's probably always there...
    }
}
