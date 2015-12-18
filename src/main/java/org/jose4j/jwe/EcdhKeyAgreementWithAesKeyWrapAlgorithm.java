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

package org.jose4j.jwe;

import org.jose4j.jca.ProviderContext;
import org.jose4j.jwa.AlgorithmInfo;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwx.Headers;
import org.jose4j.keys.AesKey;
import org.jose4j.keys.KeyPersuasion;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.InvalidKeyException;
import org.jose4j.lang.JoseException;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

/**
 */
public class EcdhKeyAgreementWithAesKeyWrapAlgorithm extends AlgorithmInfo implements KeyManagementAlgorithm
{
    private AesKeyWrapManagementAlgorithm keyWrap;

    private ContentEncryptionKeyDescriptor keyWrapKeyDescriptor;

    private EcdhKeyAgreementAlgorithm ecdh;

    public EcdhKeyAgreementWithAesKeyWrapAlgorithm(String alg, AesKeyWrapManagementAlgorithm keyWrapAlgorithm)
    {
        setAlgorithmIdentifier(alg);
        setJavaAlgorithm("N/A");
        setKeyType(EllipticCurveJsonWebKey.KEY_TYPE);
        setKeyPersuasion(KeyPersuasion.ASYMMETRIC);
        this.keyWrap = keyWrapAlgorithm;
        this.ecdh = new EcdhKeyAgreementAlgorithm(HeaderParameterNames.ALGORITHM);
        keyWrapKeyDescriptor = new ContentEncryptionKeyDescriptor(keyWrapAlgorithm.getKeyByteLength(), AesKey.ALGORITHM);
    }

    public ContentEncryptionKeys manageForEncrypt(Key managementKey, ContentEncryptionKeyDescriptor cekDesc, Headers headers, byte[] cekOverride, ProviderContext providerContext)
            throws JoseException
    {
        ContentEncryptionKeys agreedKeys = ecdh.manageForEncrypt(managementKey, keyWrapKeyDescriptor, headers, (byte[])null, providerContext);
        String contentEncryptionKeyAlgorithm = keyWrapKeyDescriptor.getContentEncryptionKeyAlgorithm();
        Key agreedKey = new SecretKeySpec(agreedKeys.getContentEncryptionKey(), contentEncryptionKeyAlgorithm);
        return keyWrap.manageForEncrypt(agreedKey, cekDesc, headers, cekOverride, providerContext);
    }

    public Key manageForDecrypt(Key managementKey, byte[] encryptedKey, ContentEncryptionKeyDescriptor cekDesc, Headers headers, ProviderContext providerContext)
            throws JoseException
    {
        Key agreedKey = ecdh.manageForDecrypt(managementKey, ByteUtil.EMPTY_BYTES, keyWrapKeyDescriptor, headers, providerContext);
        return keyWrap.manageForDecrypt(agreedKey, encryptedKey, cekDesc, headers, providerContext);
    }

    @Override
    public void validateEncryptionKey(Key managementKey, ContentEncryptionAlgorithm contentEncryptionAlg) throws InvalidKeyException
    {
        ecdh.validateEncryptionKey(managementKey, contentEncryptionAlg);
    }

    @Override
    public void validateDecryptionKey(Key managementKey, ContentEncryptionAlgorithm contentEncryptionAlg) throws InvalidKeyException
    {
        ecdh.validateDecryptionKey(managementKey, contentEncryptionAlg);
    }

    @Override
    public boolean isAvailable()
    {
        return ecdh.isAvailable() && keyWrap.isAvailable();
    }

    public static class EcdhKeyAgreementWithAes128KeyWrapAlgorithm extends EcdhKeyAgreementWithAesKeyWrapAlgorithm implements KeyManagementAlgorithm
    {
        public EcdhKeyAgreementWithAes128KeyWrapAlgorithm()
        {
            super(KeyManagementAlgorithmIdentifiers.ECDH_ES_A128KW, new AesKeyWrapManagementAlgorithm.Aes128().setUseGeneralProviderContext());
        }
    }

    public static class EcdhKeyAgreementWithAes192KeyWrapAlgorithm extends EcdhKeyAgreementWithAesKeyWrapAlgorithm implements KeyManagementAlgorithm
    {
        public EcdhKeyAgreementWithAes192KeyWrapAlgorithm()
        {
            super(KeyManagementAlgorithmIdentifiers.ECDH_ES_A192KW, new AesKeyWrapManagementAlgorithm.Aes192().setUseGeneralProviderContext());
        }
    }

    public static class EcdhKeyAgreementWithAes256KeyWrapAlgorithm extends EcdhKeyAgreementWithAesKeyWrapAlgorithm implements KeyManagementAlgorithm
    {
        public EcdhKeyAgreementWithAes256KeyWrapAlgorithm()
        {
            super(KeyManagementAlgorithmIdentifiers.ECDH_ES_A256KW, new AesKeyWrapManagementAlgorithm.Aes256().setUseGeneralProviderContext());
        }
    }
}
