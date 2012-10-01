package org.jose4j.jwx;

import junit.framework.TestCase;

import java.util.Arrays;

/**
 */
public class CompactSerializationTest extends TestCase
{
    public void testDeserialize1()
    {
        String cs = "one.two.three";
        String[] parts = CompactSerialization.deserialize(cs);
        int i = 0;
        assertEquals("one", parts[i++]);
        assertEquals("two", parts[i++]);
        assertEquals("three", parts[i++]);
        assertEquals(i, parts.length);
    }

    public void testDeserialize2()
    {
        String cs = "one.two.three.four";
        String[] parts = CompactSerialization.deserialize(cs);
        int i = 0;
        assertEquals("one", parts[i++]);
        assertEquals("two", parts[i++]);
        assertEquals("three", parts[i++]);
        assertEquals("four", parts[i++]);
        assertEquals(i, parts.length);
    }

    public void testDeserialize3()
    {
        String cs = "one.two.";
        String[] parts = CompactSerialization.deserialize(cs);
        int i = 0;
        assertEquals("one", parts[i++]);
        assertEquals("two", parts[i++]);
        assertEquals("", parts[i++]);
        assertEquals(i, parts.length);
    }

    public void testDeserialize4()
    {
        String cs = "one.two.three.";
        String[] parts = CompactSerialization.deserialize(cs);
        int i = 0;
        assertEquals("one", parts[i++]);
        assertEquals("two", parts[i++]);
        assertEquals("three", parts[i++]);
        assertEquals("", parts[i++]);
        assertEquals(i, parts.length);
    }

    public void testBadDeserialize1()
    {
        try
        {
            String cs = "one..three.four";
            String[] parts = CompactSerialization.deserialize(cs);
            fail("Empty string inside compact serialization ("+cs+") not okay " +  Arrays.toString(parts));
        }
        catch (IllegalArgumentException e)
        {
        }
    }

    public void testBadDeserialize2()
    {
        try
        {
            String cs = "one.2..four";
            String[] parts = CompactSerialization.deserialize(cs);
            fail("Empty string inside compact serialization ("+cs+") not okay " +  Arrays.toString(parts));
        }
        catch (IllegalArgumentException e)
        {
        }
    }

    public void testBadDeserialize3()
    {
        try
        {
            String cs = ".two.three.four";
            String[] parts = CompactSerialization.deserialize(cs);
            fail("Empty string inside compact serialization ("+cs+") not okay " +  Arrays.toString(parts));
        }
        catch (IllegalArgumentException e)
        {
        }
    }

    public void testSerialize1()
    {
        String cs = CompactSerialization.serialize("one", "two", "three");
        assertEquals("one.two.three", cs);
    }

    public void testSerialize2()
    {
        String cs = CompactSerialization.serialize("one", "two", "three", "four");
        assertEquals("one.two.three.four", cs);
    }

    public void testSerialize3()
    {
        String cs = CompactSerialization.serialize("one", "two", "three", null);
        assertEquals("one.two.three.", cs);
    }

    public void testSerialize4()
    {
        String cs = CompactSerialization.serialize("one", "two", "three", "");
        assertEquals("one.two.three.", cs);
    }

    public void testBadSerialize1()
    {
        try
        {
            String cs = CompactSerialization.serialize("one", "", "three", "");
            fail("serialize shouldn't work " + cs);
        }
        catch (IllegalArgumentException e)
        {
        }
    }

    public void testBadSerialize2()
    {
        try
        {
            String cs = CompactSerialization.serialize("one", null, "three", "");
            fail("serialize shouldn't work " + cs);
        }
        catch (IllegalArgumentException e)
        {
        }
    }

    public void testBadSerialize3()
    {
        try
        {
            String cs = CompactSerialization.serialize("", "two", "three", "four");
            fail("serialize shouldn't work " + cs);
        }
        catch (IllegalArgumentException e)
        {
        }
    }

    public void testBadSerialize4()
    {
        try
        {
            String cs = CompactSerialization.serialize(null, "two", "three", "four");
            fail("serialize shouldn't work " + cs);
        }
        catch (IllegalArgumentException e)
        {
        }
    }

}
