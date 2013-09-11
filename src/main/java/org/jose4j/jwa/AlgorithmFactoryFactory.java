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
import org.jose4j.jws.*;

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
        jwsAlgorithmFactory = new AlgorithmFactory<>();
        jwsAlgorithmFactory.registerAlgorithm(new PlaintextNoneAlgorithm());
        jwsAlgorithmFactory.registerAlgorithm(new HmacUsingSha256Algorithm());
        jwsAlgorithmFactory.registerAlgorithm(new HmacUsingSha384Algorithm());
        jwsAlgorithmFactory.registerAlgorithm(new HmacUsingSha512Algorithm());
        jwsAlgorithmFactory.registerAlgorithm(new EcdsaP256UsingSha256Algorithm());
        jwsAlgorithmFactory.registerAlgorithm(new EcdsaP384UsingSha384Algorithm());
        jwsAlgorithmFactory.registerAlgorithm(new EcdsaP521UsingSha512Algorithm());
        jwsAlgorithmFactory.registerAlgorithm(new RsaUsingSha256Algorithm());
        jwsAlgorithmFactory.registerAlgorithm(new RsaUsingSha384Algorithm());
        jwsAlgorithmFactory.registerAlgorithm(new RsaUsingSha512Algorithm());

        jweKeyMgmtModeAlgorithmFactory = new AlgorithmFactory<>();
        jweKeyMgmtModeAlgorithmFactory.registerAlgorithm(new Rsa1_5KeyManagementAlgorithm());
        jweKeyMgmtModeAlgorithmFactory.registerAlgorithm(new RsaOaepKeyManagementAlgorithm());
        jweKeyMgmtModeAlgorithmFactory.registerAlgorithm(new DirectKeyManagementAlgorithm());
        jweKeyMgmtModeAlgorithmFactory.registerAlgorithm(new Aes128KeyWrapManagementAlgorithm());
        jweKeyMgmtModeAlgorithmFactory.registerAlgorithm(new Aes192KeyWrapManagementAlgorithm());
        jweKeyMgmtModeAlgorithmFactory.registerAlgorithm(new Aes256KeyWrapManagementAlgorithm());
        jweKeyMgmtModeAlgorithmFactory.registerAlgorithm(new EcdhKeyAgreementAlgorithm());
        jweKeyMgmtModeAlgorithmFactory.registerAlgorithm(new EcdhKeyAgreementWithAes128KeyWrapAlgorithm());
        jweKeyMgmtModeAlgorithmFactory.registerAlgorithm(new EcdhKeyAgreementWithAes192KeyWrapAlgorithm());
        jweKeyMgmtModeAlgorithmFactory.registerAlgorithm(new EcdhKeyAgreementWithAes256KeyWrapAlgorithm());

        jweContentEncryptionAlgorithmFactory = new AlgorithmFactory<>();
        jweContentEncryptionAlgorithmFactory.registerAlgorithm(new Aes128CbcHmacSha256ContentEncryptionAlgorithm());
        jweContentEncryptionAlgorithmFactory.registerAlgorithm(new Aes192CbcHmacSha384ContentEncryptionAlgorithm());
        jweContentEncryptionAlgorithmFactory.registerAlgorithm(new Aes256CbcHmacSha512ContentEncryptionAlgorithm());
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
