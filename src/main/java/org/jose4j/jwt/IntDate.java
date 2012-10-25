package org.jose4j.jwt;

import java.util.Date;

/**
 */
public class IntDate
{
    private long value;
    private static final long CONVERSION = 1000L;

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
        return fromSeconds(millisecondsFromEpoch / CONVERSION);
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

    public long getValueInMillis()
    {
        return getValue() * CONVERSION;  
    }

    public boolean before(IntDate when)
    {
        return value < when.getValue();
    }

    public boolean after(IntDate when)
    {
        return value > when.getValue();
    }

    @Override
    public String toString()
    {
        final StringBuilder sb = new StringBuilder();
        sb.append("IntDate");
        sb.append("{").append(getValue()).append(" --> ");
        sb.append(new Date(getValueInMillis()));
        sb.append('}');                           
        return sb.toString();
    }

    @Override
    public boolean equals(Object other)
    {
        return (this == other) || ((other instanceof IntDate) && (value == ((IntDate) other).value));
    }

    @Override
    public int hashCode()
    {
        return (int) (value ^ (value >>> 32));
    }
}
