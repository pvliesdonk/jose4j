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

import org.apache.commons.logging.Log;
import org.jose4j.keys.AesKey;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.ExceptionHelp;
import org.jose4j.lang.JoseException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.GCMParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;

/**
 *                                  1
 */
public class SimpleAeadCipher
{
    public static final String GCM_TRANSFORMATION_NAME = "AES/GCM/NoPadding";

    private String algorithm;
    private int tagByteLength;


    public SimpleAeadCipher(String algorithm, int tagByteLength)
    {
        this.algorithm = algorithm;
        this.tagByteLength = tagByteLength;
    }

    private Cipher getInitialisedCipher(Key key, byte[] iv, int mode) throws JoseException
    {
        Cipher cipher = CipherUtil.getCipher(algorithm);
        try
        {
            GCMParameterSpec parameterSpec = new GCMParameterSpec(ByteUtil.bitLength(tagByteLength), iv);
            cipher.init(mode, key, parameterSpec);
            return cipher;
        }
        catch (java.security.InvalidKeyException e)
        {
            throw new JoseException("Invalid key for " + algorithm, e);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new JoseException(e.toString(), e);
        }
    }

    public CipherOutput encrypt(Key key, byte[] iv, byte[] plaintext, byte[] aad) throws JoseException
    {
        Cipher cipher = getInitialisedCipher(key, iv, Cipher.ENCRYPT_MODE);
        updateAad(cipher, aad);

        byte[] cipherOutput;
        try
        {
            cipherOutput = cipher.doFinal(plaintext);
        }
        catch (IllegalBlockSizeException | BadPaddingException e)
        {
            throw new JoseException(e.toString(), e);
        }

        CipherOutput result = new CipherOutput();
        int tagIndex = cipherOutput.length - tagByteLength;
        result.ciphertext = ByteUtil.subArray(cipherOutput, 0, tagIndex);
        result.tag = ByteUtil.subArray(cipherOutput, tagIndex, tagByteLength);
        return result;
    }

    private void updateAad(Cipher cipher, byte[] aad)
    {
        if (aad != null && aad.length > 0)
        {
            cipher.updateAAD(aad);
        }
    }

    public byte[] decrypt(Key key, byte[] iv, byte[] ciphertext, byte[] tag, byte[] aad) throws JoseException
    {
        Cipher cipher = getInitialisedCipher(key, iv, Cipher.DECRYPT_MODE);
        updateAad(cipher, aad);

        try
        {
            return cipher.doFinal(ByteUtil.concat(ciphertext,tag));
        }
        catch (IllegalBlockSizeException | BadPaddingException e)
        {
            throw new JoseException(e.toString(), e);
        }

    }

    public boolean isAvailable(Log log, int keyByteLength, int ivByteLength, String joseAlg)
    {
        boolean isAvailable = false;
        // The Sun/Oracle provider in Java 7 doesn't have GCM.
        // Bouncy Castle prior to 1.50 would let you get a cipher with AES/GCM/NoPadding but it but
        // didn't fully support the JCE AEAD interfaces and would fail (on initialization with the
        // GCMParameterSpec, IIRC) when trying to encrypt/decrypt. So seems the only good way to see if GCM
        // is really there is to try it...

        if (CipherStrengthSupport.isAvailable(algorithm, keyByteLength))
        {
            byte[] plain = new byte[] {112,108,97,105,110,116,101,120,116};
            byte[] aad = new byte[] {97,97,100};
            byte[] cek = new byte[keyByteLength];
            byte[] iv = new byte[ivByteLength];
            try
            {
                encrypt(new AesKey(cek), iv, plain, aad);
                isAvailable = true;
            }
            catch (JoseException e)
            {
                log.debug(joseAlg + " is not available (" + ExceptionHelp.toStringWithCauses(e) + ").");
            }
        }
        return isAvailable;
    }

    public static class CipherOutput
    {
        private byte[] ciphertext;
        private byte[] tag;

        public byte[] getCiphertext()
        {
            return ciphertext;
        }

        public byte[] getTag()
        {
            return tag;
        }
    }
}
