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
package org.jose4j.lang;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 *
 */
public class HashUtil
{
    public static final String SHA_256 = "SHA-256";

    public static MessageDigest getMessageDigest(String alg)
    {
        return getMessageDigest(alg, null);
    }

    public static MessageDigest getMessageDigest(String alg, String provider)
    {
        try
        {
            return provider == null ? MessageDigest.getInstance(alg) : MessageDigest.getInstance(alg, provider);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new UncheckedJoseException("Unable to get MessageDigest instance with " + alg);
        }
        catch (NoSuchProviderException e)
        {
            throw new UncheckedJoseException("Unable to get a MessageDigest implementation of algorithm name: " + alg + " using provider " + provider, e);
        }
    }
}
