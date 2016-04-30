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

package org.jose4j.base64url;

import org.jose4j.base64url.internal.apache.commons.codec.binary.Base64;
import org.jose4j.base64url.internal.apache.commons.codec.binary.BaseNCodec;

/**
 *
 */
public class SimplePEMEncoder
{
    public static String encode(final byte[] bytes)
    {
        return getCodec().encodeToString(bytes);
    }

    public static byte[] decode(final String encoded)
    {
        return getCodec().decode(encoded);
    }

    static Base64 getCodec()
    {
        return new Base64(BaseNCodec.PEM_CHUNK_SIZE);
    }
}
