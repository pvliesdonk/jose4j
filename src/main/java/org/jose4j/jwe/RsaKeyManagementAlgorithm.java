package org.jose4j.jwe;

import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwx.KeyValidationSupport;
import org.jose4j.keys.KeyPersuasion;
import org.jose4j.lang.InvalidKeyException;
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
    public void validateEncryptionKey(Key managementKey, ContentEncryptionAlgorithm contentEncryptionAlg) throws InvalidKeyException
    {
        RSAPublicKey rsaPublicKey = KeyValidationSupport.castKey(managementKey, RSAPublicKey.class);
        KeyValidationSupport.checkRsaKeySize(rsaPublicKey);
    }

    @Override
    public void validateDecryptionKey(Key managementKey, ContentEncryptionAlgorithm contentEncryptionAlg) throws InvalidKeyException
    {
        RSAPrivateKey rsaPrivateKey = KeyValidationSupport.castKey(managementKey, RSAPrivateKey.class);
        KeyValidationSupport.checkRsaKeySize(rsaPrivateKey);
    }

    @Override
    public boolean isAvailable()
    {
        try
        {
             return CipherUtil.getCipher(getJavaAlgorithm()) != null;
        }
        catch (JoseException e)
        {
            return false;
        }
    }

    public static class RsaOaep extends RsaKeyManagementAlgorithm implements KeyManagementAlgorithm
    {
        public RsaOaep()
        {
            super("RSA/ECB/OAEPWithSHA-1AndMGF1Padding", KeyManagementAlgorithmIdentifiers.RSA_OAEP);
        }
    }

    public static class RsaOaep256 extends RsaKeyManagementAlgorithm implements KeyManagementAlgorithm
    {
        public RsaOaep256()
        {
            // don't know if OAEPParameterSpec is needed...
            super("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", KeyManagementAlgorithmIdentifiers.RSA_OAEP_256);
        }
    }

    public static class Rsa1_5 extends RsaKeyManagementAlgorithm implements KeyManagementAlgorithm
    {
        public Rsa1_5()
        {
            super("RSA/ECB/PKCS1Padding", KeyManagementAlgorithmIdentifiers.RSA1_5);
        }
    }
}
