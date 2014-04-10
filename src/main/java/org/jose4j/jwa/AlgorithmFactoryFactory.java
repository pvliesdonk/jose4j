/*
 * Copyright 2012-2014 Brian Campbell
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.jwe.*;
import org.jose4j.jws.*;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.zip.CompressionAlgorithm;
import org.jose4j.zip.DeflateRFC1951CompressionAlgorithm;

/**
 */
public class AlgorithmFactoryFactory
{
    private static final AlgorithmFactoryFactory factoryFactory = new AlgorithmFactoryFactory();

    private final AlgorithmFactory<JsonWebSignatureAlgorithm> jwsAlgorithmFactory;
    private AlgorithmFactory<KeyManagementAlgorithm> jweKeyMgmtModeAlgorithmFactory;
    private AlgorithmFactory<ContentEncryptionAlgorithm> jweContentEncryptionAlgorithmFactory;
    private AlgorithmFactory<CompressionAlgorithm> compressionAlgorithmFactory;

    private AlgorithmFactoryFactory()
    {
        Log log = LogFactory.getLog(this.getClass());

        log.info("Initializing jose4j...");
        jwsAlgorithmFactory = new AlgorithmFactory<>(HeaderParameterNames.ALGORITHM, JsonWebSignatureAlgorithm.class);
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
        jwsAlgorithmFactory.registerAlgorithm(new RsaPssUsingSha256Algorithm());
        jwsAlgorithmFactory.registerAlgorithm(new RsaPssUsingSha384Algorithm());
        jwsAlgorithmFactory.registerAlgorithm(new RsaPssUsingSha512Algorithm());

        log.info("JWS signature algorithms: " + jwsAlgorithmFactory.getSupportedAlgorithms());

        jweKeyMgmtModeAlgorithmFactory = new AlgorithmFactory<>(HeaderParameterNames.ALGORITHM, KeyManagementAlgorithm.class);
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
        jweKeyMgmtModeAlgorithmFactory.registerAlgorithm(new Pbes2HmacSha256WithAes128KeyWrapAlgorithm());
        jweKeyMgmtModeAlgorithmFactory.registerAlgorithm(new Pbes2HmacSha384WithAes192KeyWrapAlgorithm());
        jweKeyMgmtModeAlgorithmFactory.registerAlgorithm(new Pbes2HmacSha512WithAes256KeyWrapAlgorithm());

        log.info("JWE key management algorithms: " + jweKeyMgmtModeAlgorithmFactory.getSupportedAlgorithms());

        jweContentEncryptionAlgorithmFactory = new AlgorithmFactory<>(HeaderParameterNames.ENCRYPTION_METHOD, ContentEncryptionAlgorithm.class);
        jweContentEncryptionAlgorithmFactory.registerAlgorithm(new Aes128CbcHmacSha256ContentEncryptionAlgorithm());
        jweContentEncryptionAlgorithmFactory.registerAlgorithm(new Aes192CbcHmacSha384ContentEncryptionAlgorithm());
        jweContentEncryptionAlgorithmFactory.registerAlgorithm(new Aes256CbcHmacSha512ContentEncryptionAlgorithm());

        log.info("JWE content encryption algorithms: " + jweContentEncryptionAlgorithmFactory.getSupportedAlgorithms());

        compressionAlgorithmFactory = new AlgorithmFactory<>(HeaderParameterNames.ZIP, CompressionAlgorithm.class);
        compressionAlgorithmFactory.registerAlgorithm(new DeflateRFC1951CompressionAlgorithm());

        log.info("JWE compression algorithms: " + compressionAlgorithmFactory.getSupportedAlgorithms());
    }

    public static AlgorithmFactoryFactory getInstance()
    {
        return factoryFactory;
    }

    public AlgorithmFactory<JsonWebSignatureAlgorithm> getJwsAlgorithmFactory()
    {
        return jwsAlgorithmFactory;
    }

    public AlgorithmFactory<KeyManagementAlgorithm> getJweKeyManagementAlgorithmFactory()
    {
        return jweKeyMgmtModeAlgorithmFactory;
    }

    public AlgorithmFactory<ContentEncryptionAlgorithm> getJweContentEncryptionAlgorithmFactory()
    {
        return jweContentEncryptionAlgorithmFactory;
    }

    public AlgorithmFactory<CompressionAlgorithm> getCompressionAlgorithmFactory()
    {
        return compressionAlgorithmFactory;
    }
}
