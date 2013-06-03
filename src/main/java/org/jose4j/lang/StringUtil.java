/*
 * Copyright 2012 Brian Campbell
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

import org.apache.commons.codec.CharEncoding;
import org.apache.commons.codec.binary.StringUtils;

/**
 */
public class StringUtil
{
    public static final String UTF_8 = CharEncoding.UTF_8;

    public static String newStringUtf8(byte[] bytes)
    {
        return newString(bytes, UTF_8);
    }

    public static String newString(byte[] bytes, String charsetName)
    {
        return StringUtils.newString(bytes, charsetName);
    }

    public static byte[] getBytesUtf8(String string)
    {
        return getBytesUnchecked(string, UTF_8);
    }

    public static byte[] getBytesAscii(String string)
    {
        return getBytesUnchecked(string, CharEncoding.US_ASCII);
    }

    public static byte[] getBytesUnchecked(String string, String charsetName)
    {
        return StringUtils.getBytesUnchecked(string, charsetName);
    }
}
