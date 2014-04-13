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

package org.jose4j.jwe;

import org.jose4j.jwa.AlgorithmAvailability;
import org.jose4j.jwa.AlgorithmInfo;
import org.jose4j.jwx.Headers;
import org.jose4j.keys.AesKey;
import org.jose4j.keys.KeyPersuasion;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.JoseException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.GCMParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

/**
 */
public class Aes256GcmContentEncryptionAlgorithm extends AlgorithmInfo implements ContentEncryptionAlgorithm
{
    public static final int IV_BYTE_LENGTH = 12;
    public static final int TAG_BYTE_LENGTH = 16;
    public static final int TAG_BIT_LENGTH = ByteUtil.bitLength(TAG_BYTE_LENGTH);

    private ContentEncryptionKeyDescriptor contentEncryptionKeyDescriptor;

    public Aes256GcmContentEncryptionAlgorithm()
    {
        setAlgorithmIdentifier("A256GCM");
        setJavaAlgorithm("AES/GCM/NoPadding");
        setKeyPersuasion(KeyPersuasion.SYMMETRIC);
        setKeyType(AesKey.ALGORITHM);
        contentEncryptionKeyDescriptor = new ContentEncryptionKeyDescriptor(256, AesKey.ALGORITHM);
    }

    public ContentEncryptionKeyDescriptor getContentEncryptionKeyDescriptor()
    {
        return contentEncryptionKeyDescriptor;
    }

    public ContentEncryptionParts encrypt(byte[] plaintext, byte[] aad, byte[] contentEncryptionKey, Headers headers, byte[] ivOverride)
            throws JoseException
    {
        byte[] iv = InitializationVectorHelp.iv(IV_BYTE_LENGTH, ivOverride);
        return encrypt(plaintext, aad, contentEncryptionKey, iv);
    }

    public ContentEncryptionParts encrypt(byte[] plaintext, byte[] aad, byte[] contentEncryptionKey, byte[] iv)
            throws JoseException
    {
        Cipher cipher = getInitialisedCipher(Cipher.ENCRYPT_MODE, iv, contentEncryptionKey);

        cipher.updateAAD(aad);

        byte[] cipherOutput;
        try
        {
            cipherOutput = cipher.doFinal(plaintext);
        }
        catch (IllegalBlockSizeException | BadPaddingException e)
        {
            throw new JoseException(e.toString(), e);
        }

        int tagIndex = cipherOutput.length - TAG_BYTE_LENGTH;
        byte[] ciphertext = ByteUtil.subArray(cipherOutput, 0, tagIndex);
        byte[] tag = ByteUtil.subArray(cipherOutput, tagIndex, TAG_BYTE_LENGTH);

        return new ContentEncryptionParts(iv, ciphertext, tag);
    }

    Cipher getInitialisedCipher(int mode, byte[] iv, byte[] rawKey) throws JoseException
    {
        Cipher cipher = CipherUtil.getCipher(getJavaAlgorithm());
        try
        {
            GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_BIT_LENGTH, iv);
            cipher.init(mode, new AesKey(rawKey), parameterSpec);
            return cipher;
        }
        catch (InvalidKeyException e)
        {
            throw new JoseException("Invalid key for " + getJavaAlgorithm(), e);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new JoseException(e.toString(), e);
        }
    }

    public byte[] decrypt(ContentEncryptionParts contentEncParts, byte[] aad, byte[] contentEncryptionKey, Headers headers)
            throws JoseException
    {
        byte[] iv = contentEncParts.getIv();
        Cipher cipher = getInitialisedCipher(Cipher.DECRYPT_MODE, iv, contentEncryptionKey);

        cipher.updateAAD(aad);

        byte[] ciphertext = ByteUtil.concat(contentEncParts.getCiphertext(), contentEncParts.getAuthenticationTag());

        try
        {
            return cipher.doFinal(ciphertext);
        }
        catch (IllegalBlockSizeException | BadPaddingException e)
        {
            throw new JoseException(e.toString(), e);
        }
    }

    @Override
    public boolean isAvailable()
    {
        // todo check for the cipher alg but also need more - BC 1.49 had it but didn't support the JCE AEAD interfaces
        int aesByteKeyLength = getContentEncryptionKeyDescriptor().getContentEncryptionKeyByteLength();
        String agl = getJavaAlgorithm();
        return AlgorithmAvailability.isAvailable("Cipher", agl) && CipherStrengthSupport.isAvailable(agl, aesByteKeyLength);
    }
}
