package org.jose4j.jwt;

/**
 */
public class IntDate
{
    private long value;

    private IntDate(long value)
    {
        this.value = value;
    }

    public static IntDate now()
    {
        return fromMillis(System.currentTimeMillis());
    }

    public static IntDate fromSeconds(long secondsFromEpoch)
    {
        return new IntDate(secondsFromEpoch);
    }

    public static IntDate fromMillis(long millisecondsFromEpoch)
    {
        return fromSeconds(millisecondsFromEpoch / 1000L);
    }

    public void addSeconds(int seconds)
    {
        value += seconds;
    }

    /**
     * Retruns a numeric value representing the number of seconds from
     * 1970-01-01T0:0:0Z UTC until the given UTC date/time
     * @return value
     */
    public long getValue()
    {
        return value;
    }
}
