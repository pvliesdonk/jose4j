/*
 * Copyright 2012-2015 Brian Campbell
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
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.zip.CompressionAlgorithm;
import org.jose4j.zip.DeflateRFC1951CompressionAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Security;
import java.util.Arrays;

/**
 */
public class AlgorithmFactoryFactory
{
    private static final Logger log = LoggerFactory.getLogger(AlgorithmFactoryFactory.class);

    private static final AlgorithmFactoryFactory factoryFactory = new AlgorithmFactoryFactory();

    private AlgorithmFactory<JsonWebSignatureAlgorithm> jwsAlgorithmFactory;
    private AlgorithmFactory<KeyManagementAlgorithm> jweKeyMgmtModeAlgorithmFactory;
    private AlgorithmFactory<ContentEncryptionAlgorithm> jweContentEncryptionAlgorithmFactory;
    private AlgorithmFactory<CompressionAlgorithm> compressionAlgorithmFactory;

    private AlgorithmFactoryFactory()
    {
        initialize();
    }

    void reinitialize()
    {
        log.info("Reinitializing jose4j...");
        initialize();
    }

    private void initialize()
    {
        String version = System.getProperty("java.version");
        String vendor = System.getProperty("java.vendor");
        String home = System.getProperty("java.home");
        String providers = Arrays.toString(Security.getProviders());
        log.info("Initializing jose4j (running with Java {} from {} at {} with {} security providers installed)...", version, vendor, home, providers);
        long startTime = System.currentTimeMillis();
        jwsAlgorithmFactory = new AlgorithmFactory<>(HeaderParameterNames.ALGORITHM, JsonWebSignatureAlgorithm.class);
        jwsAlgorithmFactory.registerAlgorithm(new PlaintextNoneAlgorithm());
        jwsAlgorithmFactory.registerAlgorithm(new HmacUsingShaAlgorithm.HmacSha256());
        jwsAlgorithmFactory.registerAlgorithm(new HmacUsingShaAlgorithm.HmacSha384());
        jwsAlgorithmFactory.registerAlgorithm(new HmacUsingShaAlgorithm.HmacSha512());
        jwsAlgorithmFactory.registerAlgorithm(new EcdsaUsingShaAlgorithm.EcdsaP256UsingSha256());
        jwsAlgorithmFactory.registerAlgorithm(new EcdsaUsingShaAlgorithm.EcdsaP384UsingSha384());
        jwsAlgorithmFactory.registerAlgorithm(new EcdsaUsingShaAlgorithm.EcdsaP521UsingSha512());
        jwsAlgorithmFactory.registerAlgorithm(new RsaUsingShaAlgorithm.RsaSha256());
        jwsAlgorithmFactory.registerAlgorithm(new RsaUsingShaAlgorithm.RsaSha384());
        jwsAlgorithmFactory.registerAlgorithm(new RsaUsingShaAlgorithm.RsaSha512());
        jwsAlgorithmFactory.registerAlgorithm(new RsaUsingShaAlgorithm.RsaPssSha256());
        jwsAlgorithmFactory.registerAlgorithm(new RsaUsingShaAlgorithm.RsaPssSha384());
        jwsAlgorithmFactory.registerAlgorithm(new RsaUsingShaAlgorithm.RsaPssSha512());

        log.info("JWS signature algorithms: {}", jwsAlgorithmFactory.getSupportedAlgorithms());

        jweKeyMgmtModeAlgorithmFactory = new AlgorithmFactory<>(HeaderParameterNames.ALGORITHM, KeyManagementAlgorithm.class);
        jweKeyMgmtModeAlgorithmFactory.registerAlgorithm(new RsaKeyManagementAlgorithm.Rsa1_5());
        jweKeyMgmtModeAlgorithmFactory.registerAlgorithm(new RsaKeyManagementAlgorithm.RsaOaep());
        jweKeyMgmtModeAlgorithmFactory.registerAlgorithm(new RsaKeyManagementAlgorithm.RsaOaep256());
        jweKeyMgmtModeAlgorithmFactory.registerAlgorithm(new DirectKeyManagementAlgorithm());
        jweKeyMgmtModeAlgorithmFactory.registerAlgorithm(new AesKeyWrapManagementAlgorithm.Aes128());
        jweKeyMgmtModeAlgorithmFactory.registerAlgorithm(new AesKeyWrapManagementAlgorithm.Aes192());
        jweKeyMgmtModeAlgorithmFactory.registerAlgorithm(new AesKeyWrapManagementAlgorithm.Aes256());
        jweKeyMgmtModeAlgorithmFactory.registerAlgorithm(new EcdhKeyAgreementAlgorithm());
        jweKeyMgmtModeAlgorithmFactory.registerAlgorithm(new EcdhKeyAgreementWithAesKeyWrapAlgorithm.EcdhKeyAgreementWithAes128KeyWrapAlgorithm());
        jweKeyMgmtModeAlgorithmFactory.registerAlgorithm(new EcdhKeyAgreementWithAesKeyWrapAlgorithm.EcdhKeyAgreementWithAes192KeyWrapAlgorithm());
        jweKeyMgmtModeAlgorithmFactory.registerAlgorithm(new EcdhKeyAgreementWithAesKeyWrapAlgorithm.EcdhKeyAgreementWithAes256KeyWrapAlgorithm());
        jweKeyMgmtModeAlgorithmFactory.registerAlgorithm(new Pbes2HmacShaWithAesKeyWrapAlgorithm.HmacSha256Aes128());
        jweKeyMgmtModeAlgorithmFactory.registerAlgorithm(new Pbes2HmacShaWithAesKeyWrapAlgorithm.HmacSha384Aes192());
        jweKeyMgmtModeAlgorithmFactory.registerAlgorithm(new Pbes2HmacShaWithAesKeyWrapAlgorithm.HmacSha512Aes256());
        jweKeyMgmtModeAlgorithmFactory.registerAlgorithm(new AesGcmKeyEncryptionAlgorithm.Aes128Gcm());
        jweKeyMgmtModeAlgorithmFactory.registerAlgorithm(new AesGcmKeyEncryptionAlgorithm.Aes192Gcm());
        jweKeyMgmtModeAlgorithmFactory.registerAlgorithm(new AesGcmKeyEncryptionAlgorithm.Aes256Gcm());

        log.info("JWE key management algorithms: {}", jweKeyMgmtModeAlgorithmFactory.getSupportedAlgorithms());

        jweContentEncryptionAlgorithmFactory = new AlgorithmFactory<>(HeaderParameterNames.ENCRYPTION_METHOD, ContentEncryptionAlgorithm.class);
        jweContentEncryptionAlgorithmFactory.registerAlgorithm(new AesCbcHmacSha2ContentEncryptionAlgorithm.Aes128CbcHmacSha256());
        jweContentEncryptionAlgorithmFactory.registerAlgorithm(new AesCbcHmacSha2ContentEncryptionAlgorithm.Aes192CbcHmacSha384());
        jweContentEncryptionAlgorithmFactory.registerAlgorithm(new AesCbcHmacSha2ContentEncryptionAlgorithm.Aes256CbcHmacSha512());
        jweContentEncryptionAlgorithmFactory.registerAlgorithm(new AesGcmContentEncryptionAlgorithm.Aes128Gcm());
        jweContentEncryptionAlgorithmFactory.registerAlgorithm(new AesGcmContentEncryptionAlgorithm.Aes192Gcm());
        jweContentEncryptionAlgorithmFactory.registerAlgorithm(new AesGcmContentEncryptionAlgorithm.Aes256Gcm());

        log.info("JWE content encryption algorithms: {}", jweContentEncryptionAlgorithmFactory.getSupportedAlgorithms());

        compressionAlgorithmFactory = new AlgorithmFactory<>(HeaderParameterNames.ZIP, CompressionAlgorithm.class);
        compressionAlgorithmFactory.registerAlgorithm(new DeflateRFC1951CompressionAlgorithm());

        log.info("JWE compression algorithms: {}", compressionAlgorithmFactory.getSupportedAlgorithms());
        log.info("Initialized jose4j in {}ms", (System.currentTimeMillis() - startTime));
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
