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
import org.jose4j.jwx.Headers;
import org.jose4j.keys.AesKey;
import org.jose4j.keys.KeyPersuasion;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.JoseException;

/**
 *
 */
public class AesGcmContentEncryptionAlgorithm extends AlgorithmInfo implements ContentEncryptionAlgorithm
{
    private static final int IV_BYTE_LENGTH = 12;
    private static final int TAG_BYTE_LENGTH = 16;

    private ContentEncryptionKeyDescriptor contentEncryptionKeyDescriptor;
    private SimpleAeadCipher simpleAeadCipher;

    public AesGcmContentEncryptionAlgorithm(String alg, int keyBitLength)
    {
        setAlgorithmIdentifier(alg);
        setJavaAlgorithm(SimpleAeadCipher.GCM_TRANSFORMATION_NAME);
        setKeyPersuasion(KeyPersuasion.SYMMETRIC);
        setKeyType(AesKey.ALGORITHM);
        contentEncryptionKeyDescriptor = new ContentEncryptionKeyDescriptor(ByteUtil.byteLength(keyBitLength), AesKey.ALGORITHM);
        simpleAeadCipher = new SimpleAeadCipher(getJavaAlgorithm(), TAG_BYTE_LENGTH);
    }

    public ContentEncryptionKeyDescriptor getContentEncryptionKeyDescriptor()
    {
        return contentEncryptionKeyDescriptor;
    }

    public ContentEncryptionParts encrypt(byte[] plaintext, byte[] aad, byte[] contentEncryptionKey, Headers headers, byte[] ivOverride, ProviderContext providerContext)
            throws JoseException
    {
        byte[] iv = InitializationVectorHelp.iv(IV_BYTE_LENGTH, ivOverride, providerContext.getSecureRandom());
        String cipherProvider = ContentEncryptionHelp.getCipherProvider(headers, providerContext);
        return encrypt(plaintext, aad, contentEncryptionKey, iv, cipherProvider);
    }



    public ContentEncryptionParts encrypt(byte[] plaintext, byte[] aad, byte[] contentEncryptionKey, byte[] iv, String provider)
            throws JoseException
    {
        AesKey cek = new AesKey(contentEncryptionKey);
        SimpleAeadCipher.CipherOutput encrypted = simpleAeadCipher.encrypt(cek, iv, plaintext, aad, provider);
        return new ContentEncryptionParts(iv, encrypted.getCiphertext(), encrypted.getTag());
    }

    public byte[] decrypt(ContentEncryptionParts contentEncParts, byte[] aad, byte[] contentEncryptionKey, Headers headers, ProviderContext providerContext)
            throws JoseException
    {
        byte[] iv = contentEncParts.getIv();
        AesKey cek = new AesKey(contentEncryptionKey);
        byte[] ciphertext = contentEncParts.getCiphertext();
        byte[] tag = contentEncParts.getAuthenticationTag();
        String cipherProvider = ContentEncryptionHelp.getCipherProvider(headers, providerContext);
        return simpleAeadCipher.decrypt(cek, iv, ciphertext, tag, aad, cipherProvider);
    }

    @Override
    public boolean isAvailable()
    {
        int keyByteLength = getContentEncryptionKeyDescriptor().getContentEncryptionKeyByteLength();
        return simpleAeadCipher.isAvailable(log, keyByteLength, IV_BYTE_LENGTH, getAlgorithmIdentifier());
    }

    public static class Aes256Gcm extends AesGcmContentEncryptionAlgorithm
    {
        public Aes256Gcm()
        {
            super(ContentEncryptionAlgorithmIdentifiers.AES_256_GCM, 256);
        }
    }

    public static class Aes192Gcm extends AesGcmContentEncryptionAlgorithm
    {
        public Aes192Gcm()
        {
            super(ContentEncryptionAlgorithmIdentifiers.AES_192_GCM, 192);
        }
    }

    public static class Aes128Gcm extends AesGcmContentEncryptionAlgorithm
    {
        public Aes128Gcm()
        {
            super(ContentEncryptionAlgorithmIdentifiers.AES_128_GCM, 128);
        }
    }
}