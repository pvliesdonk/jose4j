package org.jose4j.jwt;

import junit.framework.TestCase;

/**
 */
public class IntDateTest extends TestCase
{
    public void testBeforeAfterEquals1()
    {
        IntDate one = IntDate.fromSeconds(1350647028);
        IntDate two = IntDate.fromSeconds(1350647029);
        assertTrue(one.before(two));
        assertFalse(two.before(one));
        assertFalse(one.after(two));
        assertTrue(two.after(one));
        assertFalse(one.equals(two));
    }

    public void testBeforeAfterEquals2()
    {
        IntDate one = IntDate.fromSeconds(1350647028);
        IntDate two = IntDate.fromSeconds(1350647028);
        assertFalse(one.before(two));
        assertFalse(two.before(one));
        assertFalse(one.after(two));
        assertFalse(two.after(one));
        assertTrue(one.equals(two));
    }

    public void testEquals()
    {
        IntDate date1 = IntDate.now();
        IntDate date2 = date1;
        assertTrue(date1.equals(date2));
        assertTrue(date2.equals(date1));
        date2 = IntDate.fromSeconds(date1.getValue());
        assertTrue(date1.equals(date2));
        assertTrue(date2.equals(date1));
        date2.addSeconds(100);
        assertFalse(date1.equals(date2));
        assertFalse(date2.equals(date1));
    }
}
