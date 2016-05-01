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
package org.jose4j.jwk;

/**
 * "key_ops" (Key Operations) Parameter values as defined at
 * https://tools.ietf.org/html/rfc7517#section-4.3
 */
public class KeyOperations
{
    /**
     * compute digital signature or MAC
     */
    public static String SIGN = "sign";

    /**
     * verify digital signature or MAC
     */
    public static String VERIFY = "verify";

    /**
     * encrypt content
     */
    public static String ENCRYPT = "encrypt";

    /**
     * decrypt content and validate decryption, if applicable
     */
    public static String DECRYPT = "decrypt";

    /**
     * encrypt key
     */
    public static String WRAP_KEY = "wrapKey";

    /**
     * decrypt key and validate decryption, if applicable
     */
    public static String UNWRAP_KEY = "unwrapKey";

    /**
     *  derive key
     */
    public static String DERIVE_KEY = "deriveKey";

    /**
     *  derive bits not to be used as a key
     */
    public static String DERIVE_BITS = "deriveBits";
}
