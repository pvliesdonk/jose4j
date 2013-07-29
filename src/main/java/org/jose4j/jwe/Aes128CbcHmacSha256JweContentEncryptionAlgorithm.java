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

import org.jose4j.keys.AesKey;
import org.jose4j.keys.KeyPersuasion;
import org.jose4j.mac.MacUtil;

/**
 */
public class Aes128CbcHmacSha256JweContentEncryptionAlgorithm
        extends GenericAesCbcHmacSha2JweContentEncryptionAlgorithm
        implements JsonWebEncryptionContentEncryptionAlgorithm
{
    public Aes128CbcHmacSha256JweContentEncryptionAlgorithm()
    {
        super();
        setAlgorithmIdentifier(EncryptionMethodAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        setKeySize(32); // 16 octets for MAC_KEY_LEN + 16 octets for ENC_KEY_LEN
        setHmacJavaAlgorithm(MacUtil.HMAC_SHA256);
        setTagTruncationLength(16); // The HMAC-SHA-256 output is truncated to T_LEN=16 octets
        this.setKeyPersuasion(KeyPersuasion.SYMMETRIC);
        this.setKeyType(AesKey.ALGORITHM);
    }
}
