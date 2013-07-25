/*
 * Copyright 2012-2013 Brian Campbell
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jose4j.jwa;

import org.jose4j.jwe.*;
import org.jose4j.jws.JsonWebSignatureAlgorithm;
import org.jose4j.keys.KeyPersuasion;

import java.security.Key;

/**
 */
public class AlgorithmFactoryFactory
{
    private static final AlgorithmFactoryFactory factoryFactory = new AlgorithmFactoryFactory();

    private final AlgorithmFactory<JsonWebSignatureAlgorithm> jwsAlgorithmFactory;
    private AlgorithmFactory<JsonWebEncryptionKeyManagementModeAlgorithm> jweKeyMgmtModeAlgorithmFactory;
    private AlgorithmFactory<JsonWebEncryptionEncryptionMethodAlgorithm> jweEncMethodAlgorithmFactory;


    private AlgorithmFactoryFactory()
    {
        jwsAlgorithmFactory = new AlgorithmFactory<JsonWebSignatureAlgorithm>("jws-algorithms.properties"); // todo change name
        jweKeyMgmtModeAlgorithmFactory = new AlgorithmFactory<JsonWebEncryptionKeyManagementModeAlgorithm>("todo.properties");
        jweEncMethodAlgorithmFactory = new AlgorithmFactory<JsonWebEncryptionEncryptionMethodAlgorithm>("todo.properties");

    }

    public static AlgorithmFactoryFactory getInstance()
    {
        return factoryFactory;
    }

    public AlgorithmFactory<JsonWebSignatureAlgorithm> getJwsAlgorithmFactory()
    {
        return jwsAlgorithmFactory;
    }

    public JsonWebEncryptionKeyManagementModeAlgorithm getKeyManagementModeAlgorithm(String algo)
    {
        // TODO
        if (KeyManagementModeAlgorithmIdentifiers.RSA1_5.equals(algo))
        {
            return new JsonWebEncryptionKeyManagementModeAlgorithm()
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

                public KeyPersuasion getKeyPersuasion()
                {
                    return null;  //To change body of implemented methods use File | Settings | File Templates.
                }

                public String getKeyType()
                {
                    return null;  //To change body of implemented methods use File | Settings | File Templates.
                }
            };
        }

        return null;
    }

    public JsonWebEncryptionEncryptionMethodAlgorithm getSymmetricEncryptionAlgorithm(String algo)
    {
        if (!algo.equals(EncryptionMethodAlgorithmIdentifiers.A128CBC))
        {
            return null;
        }
        return new Aes128CbcJsonWebEncryptionEncryptionAlgorithm();
    }
}
