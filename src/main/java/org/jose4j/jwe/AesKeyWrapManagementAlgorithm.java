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
import org.jose4j.keys.AesKey;
import org.jose4j.keys.KeyPersuasion;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.JoseException;

import javax.crypto.Cipher;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

/**
 */
public class AesKeyWrapManagementAlgorithm extends WrappingKeyManagementAlgorithm
{
    int keyByteLength;

    public AesKeyWrapManagementAlgorithm(String alg, int keyByteLength)
    {
        super("AESWrap", alg);
        setKeyType(AesKey.ALGORITHM);
        setKeyPersuasion(KeyPersuasion.SYMMETRIC);
        this.keyByteLength = keyByteLength;
    }

    int getKeyByteLength()
    {
        return keyByteLength;
    }

    @Override
    public void validateEncryptionKey(Key managementKey, ContentEncryptionAlgorithm contentEncryptionAlg) throws JoseException
    {
        validateKey(managementKey);
    }

    @Override
    public void validateDecryptionKey(Key managementKey, ContentEncryptionAlgorithm contentEncryptionAlg) throws JoseException
    {
        validateKey(managementKey);
    }

    void validateKey(Key managementKey) throws JoseException
    {
        if (managementKey == null)
        {
            throw new JoseException("The key must not be null.");
        }

        String alg = managementKey.getAlgorithm();

        if (!AesKey.ALGORITHM.equals(alg))
        {
            throw new JoseException("Invalid key for JWE " + getAlgorithmIdentifier() + ", expected an "
                               + AesKey.ALGORITHM+ " key but an " + alg + " bit key was provided.");
        }

        int managementKeyByteLength = managementKey.getEncoded().length;
        if (managementKeyByteLength != getKeyByteLength())
        {
           throw new JoseException("Invalid key for JWE " + getAlgorithmIdentifier() + ", expected a "
                   + ByteUtil.bitLength(getKeyByteLength())+ " bit key but a "
                   + ByteUtil.bitLength(managementKeyByteLength) + " bit key was provided.");
        }
    }

    @Override
    public boolean isAvailable()
    {
        int aesByteKeyLength = getKeyByteLength();
        String agl = getJavaAlgorithm();
        return AlgorithmAvailability.isAvailable("Cipher", agl) && CipherStrengthSupport.isAvailable(agl, aesByteKeyLength);
    }
}
