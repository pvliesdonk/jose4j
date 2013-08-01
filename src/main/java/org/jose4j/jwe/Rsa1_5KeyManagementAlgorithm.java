package org.jose4j.jwe;

import org.jose4j.jwa.AlgorithmInfo;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.keys.KeyPersuasion;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.JoseException;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;

/**
 */
public class Rsa1_5KeyManagementAlgorithm extends RsaKeyManagementAlgorithm implements KeyManagementAlgorithm
{
    public Rsa1_5KeyManagementAlgorithm()
    {
        super("RSA/ECB/PKCS1Padding", KeyManagementAlgorithmIdentifiers.RSA1_5);

    }
}
