/*
 * Copyright 2012-2014 Brian Campbell
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

package org.jose4j.jwt;

import java.text.DateFormat;
import java.util.Date;

// TODO the whole "non-integer values can be represented" thing is there though it looks like maybe that's always been possible and I just assumed not b/c of the former IntDate name. Not sure how much support is needed for that (other than not failing) but maybe...

/**
 */
public class NumericDate
{
    private long value;
    private static final long CONVERSION = 1000L;

    private NumericDate(long value)
    {
        this.value = value;
    }

    public static NumericDate now()
    {
        return fromMilliseconds(System.currentTimeMillis());
    }

    public static NumericDate fromSeconds(long secondsFromEpoch)
    {
        return new NumericDate(secondsFromEpoch);
    }

    public static NumericDate fromMilliseconds(long millisecondsFromEpoch)
    {
        return fromSeconds(millisecondsFromEpoch / CONVERSION);
    }

    public void addSeconds(long seconds)
    {
        value += seconds;
    }

    /**
     * Returns a numeric value representing the number of seconds from
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

    public boolean isBefore(NumericDate when)
    {
        return value < when.getValue();
    }

    public boolean isOnOrAfter(NumericDate when)
    {
        return !isBefore(when);
    }

    public boolean isAfter(NumericDate when)
    {
        return value > when.getValue();
    }

    @Override
    public String toString()
    {
        DateFormat df  = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.LONG);
        StringBuilder sb = new StringBuilder();
        Date date = new Date(getValueInMillis());
        sb.append("NumericDate").append("{").append(getValue()).append(" -> ").append(df.format(date)).append('}');
        return sb.toString();
    }

    @Override
    public boolean equals(Object other)
    {
        return (this == other) || ((other instanceof NumericDate) && (value == ((NumericDate) other).value));
    }

    @Override
    public int hashCode()
    {
        return (int) (value ^ (value >>> 32));
    }
}
