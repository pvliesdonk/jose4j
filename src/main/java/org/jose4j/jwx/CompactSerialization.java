/*
 * Copyright 2012-2015 Brian Campbell
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
package org.jose4j.jwx;

import org.jose4j.lang.JoseException;

/**
 * @deprecated please use CompactSerializer
 *
 * This class was added back in as of 0.3.7 to help support code compiled against pre v0.3.0 that was using it directly.
 */
public class CompactSerialization
{
    /**
     * @deprecated please use CompactSerializer
     */
    public static String[] deserialize(String cs)
    {
        return CompactSerializer.deserialize(cs);
    }

    /**
     * @deprecated please use CompactSerializer
     */
    public static String serialize(String... parts) throws JoseException
    {
        return CompactSerializer.serialize(parts);
    }
}
