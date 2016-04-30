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

import org.jose4j.lang.ByteUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;

import java.security.NoSuchAlgorithmException;

/**
 */
public class CipherStrengthSupport
{
    private static final Logger log = LoggerFactory.getLogger(CipherStrengthSupport.class);

    public static boolean isAvailable(String algorithm, int keyByteLength)
    {
        boolean isAvailable;
        int bitKeyLength = ByteUtil.bitLength(keyByteLength);
        try
        {
            int maxAllowedKeyLength = Cipher.getMaxAllowedKeyLength(algorithm);
            isAvailable = (bitKeyLength <= maxAllowedKeyLength);

            if (!isAvailable)
            {
                log.debug("max allowed key length for {} is {}", algorithm, maxAllowedKeyLength);
            }
        }
        catch (NoSuchAlgorithmException e)
        {
            log.debug("Unknown/unsupported algorithm, {} {}", algorithm, e);
            isAvailable = false;
        }
        return isAvailable;
    }

}
