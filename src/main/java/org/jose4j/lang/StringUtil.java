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

    public static byte[] getBytesUnchecked(String string, String charsetName)
    {
        return StringUtils.getBytesUnchecked(string, charsetName);
    }
}
