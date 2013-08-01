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
import org.jose4j.lang.JoseException;

/**
 */
public class AlgorithmFactoryFactory
{
    private static final AlgorithmFactoryFactory factoryFactory = new AlgorithmFactoryFactory();

    private final AlgorithmFactory<JsonWebSignatureAlgorithm> jwsAlgorithmFactory;
    private AlgorithmFactory<KeyManagementAlgorithm> jweKeyMgmtModeAlgorithmFactory;
    private AlgorithmFactory<ContentEncryptionAlgorithm> jweContentEncryptionAlgorithmFactory;


    private AlgorithmFactoryFactory()
    {
        jwsAlgorithmFactory = new AlgorithmFactory<JsonWebSignatureAlgorithm>("jws-algorithms.properties"); // todo change name (not sure why the todo was put here?)
        jweKeyMgmtModeAlgorithmFactory = new AlgorithmFactory<KeyManagementAlgorithm>("jwe-key-management-algorithms.properties");
        jweContentEncryptionAlgorithmFactory = new AlgorithmFactory<ContentEncryptionAlgorithm>("jwe-content-encryption-algorithms.properties");

    }

    public static AlgorithmFactoryFactory getInstance()
    {
        return factoryFactory;
    }

    public AlgorithmFactory<JsonWebSignatureAlgorithm> getJwsAlgorithmFactory()
    {
        return jwsAlgorithmFactory;
    }

    public AlgorithmFactory<KeyManagementAlgorithm> getKeyManagementAlgorithmFactory()
    {
        return jweKeyMgmtModeAlgorithmFactory;
    }

    public AlgorithmFactory<ContentEncryptionAlgorithm> getJweContentEncryptionAlgorithmFactory()
    {
        return jweContentEncryptionAlgorithmFactory;
    }
}
