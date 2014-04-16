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
package org.jose4j.jwe;

import org.jose4j.base64url.Base64Url;
import org.jose4j.jwa.AlgorithmInfo;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwx.Headers;
import org.jose4j.keys.AesKey;
import org.jose4j.keys.KeyPersuasion;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.InvalidKeyException;
import org.jose4j.lang.JoseException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;

/**
 *
 */
public class AesGcmKeyEncryptionAlgorithm extends AlgorithmInfo implements KeyManagementAlgorithm
{
    public static final int TAG_BIT_LENGTH = 128;
    public static final int TAG_BYTE_LENGTH = ByteUtil.byteLength(TAG_BIT_LENGTH);
    public static final int IV_BYTE_LENGTH = 12;

    public AesGcmKeyEncryptionAlgorithm(String alg)
    {
        setAlgorithmIdentifier(alg);
        setJavaAlgorithm("AES/GCM/NoPadding");
        setKeyPersuasion(KeyPersuasion.SYMMETRIC);
        setKeyType(AesKey.ALGORITHM);
    }

    @Override
    public ContentEncryptionKeys manageForEncrypt(Key managementKey, ContentEncryptionKeyDescriptor cekDesc, Headers headers, byte[] cekOverride) throws JoseException
    {
        byte[] cek = (cekOverride == null) ? ByteUtil.randomBytes(cekDesc.getContentEncryptionKeyByteLength()) : cekOverride;

        Base64Url base64Url = new Base64Url();

        String encodedIv = headers.getStringHeaderValue(HeaderParameterNames.INITIALIZATION_VECTOR);
        byte[] iv;
        if (encodedIv == null)
        {
            iv = ByteUtil.randomBytes(IV_BYTE_LENGTH);
            encodedIv = base64Url.base64UrlEncode(iv);
            headers.setStringHeaderValue(HeaderParameterNames.INITIALIZATION_VECTOR, encodedIv);
        }
        else
        {
            iv = base64Url.base64UrlDecode(encodedIv);
        }

        int mode = Cipher.ENCRYPT_MODE;

        Cipher cipher = getInitialisedCipher(managementKey, iv, mode);

        try
        {
            byte[] ciphertext = cipher.doFinal(cek);

            // todo extract some common GCM cipher things to somewhere and use with content enc too
            int tagIndex = ciphertext.length - TAG_BYTE_LENGTH;
            byte[] encryptedKey = ByteUtil.subArray(ciphertext, 0, tagIndex);
            byte[] tag = ByteUtil.subArray(ciphertext, tagIndex, TAG_BYTE_LENGTH);

            String encodedTag = base64Url.base64UrlEncode(tag);
            headers.setStringHeaderValue(HeaderParameterNames.AUTHENTICATION_TAG, encodedTag);

            return new ContentEncryptionKeys(cek, encryptedKey);
        }
        catch (IllegalBlockSizeException | BadPaddingException e)
        {
            throw new JoseException(e.toString(), e);
        }
    }

    private Cipher getInitialisedCipher(Key key, byte[] iv, int mode) throws JoseException
    {
        Cipher cipher = CipherUtil.getCipher(getJavaAlgorithm());
        try
        {
            GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_BIT_LENGTH, iv);
            cipher.init(mode, key, parameterSpec);
            return cipher;
        }
        catch (java.security.InvalidKeyException e)
        {
            throw new JoseException("Invalid key for " + getJavaAlgorithm(), e);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new JoseException(e.toString(), e);
        }
    }

    @Override
    public Key manageForDecrypt(Key managementKey, byte[] encryptedKey, ContentEncryptionKeyDescriptor cekDesc, Headers headers) throws JoseException
    {
        Base64Url base64Url = new Base64Url();
        String encodedIv = headers.getStringHeaderValue(HeaderParameterNames.INITIALIZATION_VECTOR);
        byte[] iv = base64Url.base64UrlDecode(encodedIv);

        Cipher cipher = getInitialisedCipher(managementKey, iv, Cipher.DECRYPT_MODE);

        String encodedTag = headers.getStringHeaderValue(HeaderParameterNames.AUTHENTICATION_TAG);
        byte[] tag = base64Url.base64UrlDecode(encodedTag);
        byte[] ciphertext = ByteUtil.concat(encryptedKey, tag);
        try
        {
            byte[] cek = cipher.doFinal(ciphertext);
            return new SecretKeySpec(cek, cekDesc.getContentEncryptionKeyAlgorithm());
        }
        catch (IllegalBlockSizeException | BadPaddingException e)
        {
            throw new JoseException(e.toString(), e);
        }
    }

    @Override
    public void validateEncryptionKey(Key managementKey, ContentEncryptionAlgorithm contentEncryptionAlg) throws InvalidKeyException
    {
        // todo
    }

    @Override
    public void validateDecryptionKey(Key managementKey, ContentEncryptionAlgorithm contentEncryptionAlg) throws InvalidKeyException
    {
        // todo
    }

    @Override
    public boolean isAvailable()
    {
        return true;  // todo
    }

    public static class Aes128Gcm extends AesGcmKeyEncryptionAlgorithm
    {
        public Aes128Gcm()
        {
            super(KeyManagementAlgorithmIdentifiers.A128GCMKW);
        }
    }

    public static class Aes192Gcm extends AesGcmKeyEncryptionAlgorithm
    {
        public Aes192Gcm()
        {
            super(KeyManagementAlgorithmIdentifiers.A192GCMKW);
        }
    }

    public static class Aes256Gcm extends AesGcmKeyEncryptionAlgorithm
    {
        public Aes256Gcm()
        {
            super(KeyManagementAlgorithmIdentifiers.A256GCMKW);
        }
    }
}
