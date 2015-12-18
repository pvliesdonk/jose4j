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

import org.jose4j.base64url.Base64Url;
import org.jose4j.jca.ProviderContext;
import org.jose4j.jwa.AlgorithmInfo;
import org.jose4j.jwk.OctetSequenceJsonWebKey;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwx.Headers;
import org.jose4j.jwx.KeyValidationSupport;
import org.jose4j.keys.KeyPersuasion;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.InvalidKeyException;
import org.jose4j.lang.JoseException;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;

/**
 *
 */
public class AesGcmKeyEncryptionAlgorithm extends AlgorithmInfo implements KeyManagementAlgorithm
{
    private static final int TAG_BYTE_LENGTH = 16;
    private static final int IV_BYTE_LENGTH = 12;

    private SimpleAeadCipher simpleAeadCipher;
    private int keyByteLength;

    public AesGcmKeyEncryptionAlgorithm(String alg, int keyByteLength)
    {
        setAlgorithmIdentifier(alg);
        setJavaAlgorithm(SimpleAeadCipher.GCM_TRANSFORMATION_NAME);
        setKeyPersuasion(KeyPersuasion.SYMMETRIC);
        setKeyType(OctetSequenceJsonWebKey.KEY_TYPE);
        simpleAeadCipher = new SimpleAeadCipher(getJavaAlgorithm(), TAG_BYTE_LENGTH);
        this.keyByteLength = keyByteLength;
    }

    @Override
    public ContentEncryptionKeys manageForEncrypt(Key managementKey, ContentEncryptionKeyDescriptor cekDesc, Headers headers, byte[] cekOverride, ProviderContext providerContext) throws JoseException
    {
        SecureRandom secureRandom = providerContext.getSecureRandom();
        byte[] cek = (cekOverride == null) ? ByteUtil.randomBytes(cekDesc.getContentEncryptionKeyByteLength(), secureRandom) : cekOverride;

        Base64Url base64Url = new Base64Url();

        String encodedIv = headers.getStringHeaderValue(HeaderParameterNames.INITIALIZATION_VECTOR);
        byte[] iv;
        if (encodedIv == null)
        {
            iv = ByteUtil.randomBytes(IV_BYTE_LENGTH, secureRandom);
            encodedIv = base64Url.base64UrlEncode(iv);
            headers.setStringHeaderValue(HeaderParameterNames.INITIALIZATION_VECTOR, encodedIv);
        }
        else
        {
            iv = base64Url.base64UrlDecode(encodedIv);
        }

        String cipherProvider = providerContext.getSuppliedKeyProviderContext().getCipherProvider();
        SimpleAeadCipher.CipherOutput encrypted = simpleAeadCipher.encrypt(managementKey, iv, cek, null, cipherProvider);
        byte[] encryptedKey = encrypted.getCiphertext();
        byte[] tag = encrypted.getTag();

        String encodedTag = base64Url.base64UrlEncode(tag);
        headers.setStringHeaderValue(HeaderParameterNames.AUTHENTICATION_TAG, encodedTag);

        return new ContentEncryptionKeys(cek, encryptedKey);
    }

    @Override
    public Key manageForDecrypt(Key managementKey, byte[] encryptedKey, ContentEncryptionKeyDescriptor cekDesc, Headers headers, ProviderContext providerContext) throws JoseException
    {
        Base64Url base64Url = new Base64Url();
        String encodedIv = headers.getStringHeaderValue(HeaderParameterNames.INITIALIZATION_VECTOR);
        byte[] iv = base64Url.base64UrlDecode(encodedIv);

        String encodedTag = headers.getStringHeaderValue(HeaderParameterNames.AUTHENTICATION_TAG);
        byte[] tag = base64Url.base64UrlDecode(encodedTag);

        String cipherProvider = providerContext.getSuppliedKeyProviderContext().getCipherProvider();
        byte[] cek = simpleAeadCipher.decrypt(managementKey, iv, encryptedKey, tag, null, cipherProvider);
        return new SecretKeySpec(cek, cekDesc.getContentEncryptionKeyAlgorithm());
    }

    @Override
    public void validateEncryptionKey(Key managementKey, ContentEncryptionAlgorithm contentEncryptionAlg) throws InvalidKeyException
    {
        validateKey(managementKey);
    }

    @Override
    public void validateDecryptionKey(Key managementKey, ContentEncryptionAlgorithm contentEncryptionAlg) throws InvalidKeyException
    {
        validateKey(managementKey);
    }

    void validateKey(Key managementKey) throws InvalidKeyException
    {
        KeyValidationSupport.validateAesWrappingKey(managementKey, getAlgorithmIdentifier(), keyByteLength);
    }


    @Override
    public boolean isAvailable()
    {
        return simpleAeadCipher.isAvailable(log, keyByteLength, IV_BYTE_LENGTH, getAlgorithmIdentifier());
    }

    public static class Aes128Gcm extends AesGcmKeyEncryptionAlgorithm
    {
        public Aes128Gcm()
        {
            super(KeyManagementAlgorithmIdentifiers.A128GCMKW, ByteUtil.byteLength(128));
        }
    }

    public static class Aes192Gcm extends AesGcmKeyEncryptionAlgorithm
    {
        public Aes192Gcm()
        {
            super(KeyManagementAlgorithmIdentifiers.A192GCMKW, ByteUtil.byteLength(192));
        }
    }

    public static class Aes256Gcm extends AesGcmKeyEncryptionAlgorithm
    {
        public Aes256Gcm()
        {
            super(KeyManagementAlgorithmIdentifiers.A256GCMKW, ByteUtil.byteLength(256));
        }
    }
}
