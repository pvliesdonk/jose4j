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
    private AlgorithmFactory<KeyManagementModeAlgorithm> jweKeyMgmtModeAlgorithmFactory;
    private AlgorithmFactory<ContentEncryptionAlgorithm> jweEncMethodAlgorithmFactory;


    private AlgorithmFactoryFactory()
    {
        jwsAlgorithmFactory = new AlgorithmFactory<JsonWebSignatureAlgorithm>("jws-algorithms.properties"); // todo change name
        jweKeyMgmtModeAlgorithmFactory = new AlgorithmFactory<KeyManagementModeAlgorithm>("todo.properties");
        jweEncMethodAlgorithmFactory = new AlgorithmFactory<ContentEncryptionAlgorithm>("todo.properties");

    }

    public static AlgorithmFactoryFactory getInstance()
    {
        return factoryFactory;
    }

    public AlgorithmFactory<JsonWebSignatureAlgorithm> getJwsAlgorithmFactory()
    {
        return jwsAlgorithmFactory;
    }

    public KeyManagementModeAlgorithm getKeyManagementModeAlgorithm(String algo)
    {
        // TODO
        if (KeyManagementModeAlgorithmIdentifiers.RSA1_5.equals(algo))
        {
            return new Rsa1_5KeyManagementModeAlgorithm();
        }

        return null;
    }

    public ContentEncryptionAlgorithm getSymmetricEncryptionAlgorithm(String algo)
    {
        if (!algo.equals(EncryptionMethodAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256))
        {
            return null;
        }
        return new Aes128CbcHmacSha256ContentEncryptionAlgorithm();
    }
}
