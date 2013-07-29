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

import org.jose4j.jwa.Algorithm;
import org.jose4j.lang.JoseException;

/**
 */
public interface ContentEncryptionAlgorithm extends Algorithm
{
    /**
     * Gets the key size.
     *
     * @return the length, in bytes, of the key used by this algorithm
     */
    int getKeySize();

    EncryptionResult encrypt(byte[] plaintext, byte[] aad, byte[] key) throws JoseException;
    byte[] decrypt(byte[] cipherText, byte[] iv, byte[] aad, byte[] tag, byte[] key) throws JoseException;

    public static class EncryptionResult
    {
        private byte[] iv;
        private byte[] ciphertext;
        private byte[] authenticationTag;

        public EncryptionResult(byte[] iv, byte[] ciphertext, byte[] authenticationTag)
        {
            this.iv = iv;
            this.ciphertext = ciphertext;
            this.authenticationTag = authenticationTag;
        }

        public byte[] getIv()
        {
            return iv;
        }

        public byte[] getCiphertext()
        {
            return ciphertext;
        }

        public byte[] getAuthenticationTag()
        {
            return authenticationTag;
        }
    }
}