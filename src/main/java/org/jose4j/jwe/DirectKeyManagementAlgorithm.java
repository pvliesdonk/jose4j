/*
 * Copyright 2012-2016 Brian Campbell
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
import org.jose4j.jwk.OctetSequenceJsonWebKey;
import org.jose4j.jwx.Headers;
import org.jose4j.jwx.KeyValidationSupport;
import org.jose4j.keys.KeyPersuasion;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.InvalidKeyException;
import org.jose4j.lang.JoseException;

import java.security.Key;

/**
 */
public class DirectKeyManagementAlgorithm extends AlgorithmInfo implements KeyManagementAlgorithm
{
    public DirectKeyManagementAlgorithm()
    {
        setAlgorithmIdentifier(KeyManagementAlgorithmIdentifiers.DIRECT);
        setKeyPersuasion(KeyPersuasion.SYMMETRIC);
        setKeyType(OctetSequenceJsonWebKey.KEY_TYPE);
    }

    public ContentEncryptionKeys manageForEncrypt(Key managementKey, ContentEncryptionKeyDescriptor cekDesc, Headers headers, byte[] cekOverride, ProviderContext providerContext) throws JoseException
    {
        KeyValidationSupport.cekNotAllowed(cekOverride, getAlgorithmIdentifier());
        byte[] cekBytes = managementKey.getEncoded();
        return new ContentEncryptionKeys(cekBytes, ByteUtil.EMPTY_BYTES);
    }

    public Key manageForDecrypt(Key managementKey, byte[] encryptedKey, ContentEncryptionKeyDescriptor cekDesc, Headers headers, ProviderContext providerContext) throws JoseException
    {
        if (encryptedKey.length != 0)
        {
            throw new InvalidKeyException("An empty octet sequence is to be used as the JWE Encrypted Key value when utilizing " +
                    "direct encryption but this JWE has " + encryptedKey.length + " octets in the encrypted key part.");
        }
        return managementKey;
    }

    @Override
    public void validateEncryptionKey(Key managementKey, ContentEncryptionAlgorithm contentEncryptionAlg) throws InvalidKeyException
    {
        validateKey(managementKey, contentEncryptionAlg);
    }

    private void validateKey(Key managementKey, ContentEncryptionAlgorithm contentEncryptionAlg) throws InvalidKeyException
    {
        KeyValidationSupport.notNull(managementKey);

        if (managementKey.getEncoded() != null)
        {
            int managementKeyByteLength = managementKey.getEncoded().length;
            int expectedByteLength = contentEncryptionAlg.getContentEncryptionKeyDescriptor().getContentEncryptionKeyByteLength();
            if (expectedByteLength != managementKeyByteLength)
            {
                throw new InvalidKeyException("Invalid key for " + getAlgorithmIdentifier() + " with "
                                  + contentEncryptionAlg.getAlgorithmIdentifier() +", expected a "
                                  + ByteUtil.bitLength(expectedByteLength)+ " bit key but a "
                                  + ByteUtil.bitLength(managementKeyByteLength) + " bit key was provided.");
            }
        }
    }

    @Override
    public void validateDecryptionKey(Key managementKey, ContentEncryptionAlgorithm contentEncryptionAlg) throws InvalidKeyException
    {
        validateKey(managementKey, contentEncryptionAlg);
    }

    @Override
    public boolean isAvailable()
    {
        return true;
    }
}
