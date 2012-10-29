package org.jose4j.jwa;

import org.jose4j.jws.*;
import org.jose4j.jwe.*;
import org.jose4j.keys.KeyType;

import java.security.Key;

/**
 */
public class AlgorithmFactoryFactory
{
    private static final AlgorithmFactoryFactory factoryFactory = new AlgorithmFactoryFactory();

    private final AlgorithmFactory<JsonWebSignatureAlgorithm> jwsAlgorithmFactory;
    private AlgorithmFactory<KeyEncryptionAlgorithm> jweKeyEncAlgorithmFactory;
    private AlgorithmFactory<SymmetricEncryptionAlgorithm> jweSymmEncAlgorithmFactory;


    private AlgorithmFactoryFactory()
    {
        jwsAlgorithmFactory = new AlgorithmFactory<JsonWebSignatureAlgorithm>("jws-algorithms.properties"); // todo change name
        jweKeyEncAlgorithmFactory = new AlgorithmFactory<KeyEncryptionAlgorithm>("todo.properties");
        jweSymmEncAlgorithmFactory = new AlgorithmFactory<SymmetricEncryptionAlgorithm>("todo.properties");

    }

    public static AlgorithmFactoryFactory getInstance()
    {
        return factoryFactory;
    }

    public AlgorithmFactory<JsonWebSignatureAlgorithm> getJwsAlgorithmFactory()
    {
        return jwsAlgorithmFactory;
    }

    public KeyEncryptionAlgorithm getKeyEncryptionAlgorithm(String algo)
    {
        // TODO
        if (KeyEncryptionAlgorithmIdentifiers.RSA1_5.equals(algo))
        {
            return new KeyEncryptionAlgorithm()
            {
                public byte[] encrypt(Key key, byte[] contentMasterKey)
                {
                    return contentMasterKey; // TODO
                }

                public String getJavaAlgorithm()
                {
                    return null;  //To change body of implemented methods use File | Settings | File Templates.
                }

                public String getAlgorithmIdentifier()
                {
                    return null;  //To change body of implemented methods use File | Settings | File Templates.
                }

                public KeyType getKeyType()
                {
                    return null;  //To change body of implemented methods use File | Settings | File Templates.
                }

                public String getKeyAlgorithm()
                {
                    return null;  //To change body of implemented methods use File | Settings | File Templates.
                }
            };
        }

        return null;
    }

    public SymmetricEncryptionAlgorithm getSymmetricEncryptionAlgorithm(String algo)
    {
        if (!algo.equals(SymmetricEncryptionAlgorithmIdentifiers.A128CBC))
        {
            return null;
        }
        return new Aes128CbcSymmetricEncryptionAlgorithm();
    }
}
