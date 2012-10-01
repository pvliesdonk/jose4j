package org.jose4j.jwx;

/**
 */
public class CompactSerialization
{
    private static final String PERIOD_SEPARATOR = ".";
    private static final String PERIOD_SEPARATOR_REGEX = "\\.";

    private static final String EMPTY_STRING = "";

    private static final String NO_EMPTY_PARTS_MSG = "Compact serialization cannot contain empty middle or beginning parts.";

    public static String[] deserialize(String compactSerialization)
    {
        String[] parts = compactSerialization.split(PERIOD_SEPARATOR_REGEX);

        for (String part : parts)
        {
            if (EMPTY_STRING.equals(part))
            {
                throw new IllegalArgumentException(NO_EMPTY_PARTS_MSG);
            }
        }

        if (compactSerialization.endsWith(PERIOD_SEPARATOR))
        {
            String[] tempParts = new String[parts.length + 1];
            System.arraycopy(parts, 0, tempParts, 0, parts.length);
            tempParts[parts.length] = EMPTY_STRING;
            parts = tempParts;
        }

        return parts;
    }

    public static String serialize(String... parts)
    {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < parts.length; i++)
        {
            String part = (parts[i] == null) ? EMPTY_STRING : parts[i];
            sb.append(part);
            if (i != parts.length - 1)
            {
                if (EMPTY_STRING.equals(part))
                {
                    throw new IllegalArgumentException(NO_EMPTY_PARTS_MSG);
                }
                sb.append(PERIOD_SEPARATOR);
            }
        }
        return sb.toString();
    }
}
