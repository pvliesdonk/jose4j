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

package org.jose4j.jwx;

import junit.framework.TestCase;
import org.jose4j.lang.JoseException;

import java.util.Arrays;

/**
 */
public class CompactSerializationTest extends TestCase
{
    public void testDeserialize1() throws JoseException
    {
        String cs = "one.two.three";
        String[] parts = CompactSerialization.deserialize(cs);
        int i = 0;
        assertEquals("one", parts[i++]);
        assertEquals("two", parts[i++]);
        assertEquals("three", parts[i++]);
        assertEquals(i, parts.length);
    }

    public void testDeserialize2()  throws JoseException
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

    public void testDeserialize3() throws JoseException
    {
        String cs = "one.two.";
        String[] parts = CompactSerialization.deserialize(cs);
        int i = 0;
        assertEquals("one", parts[i++]);
        assertEquals("two", parts[i++]);
        assertEquals("", parts[i++]);
        assertEquals(i, parts.length);
    }

    public void testDeserialize4() throws JoseException
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
        catch (JoseException e)
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
        catch (JoseException e)
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
        catch (JoseException e)
        {
        }
    }

    public void testSerialize1() throws JoseException
    {
        String cs = CompactSerialization.serialize("one", "two", "three");
        assertEquals("one.two.three", cs);
    }

    public void testSerialize2() throws JoseException
    {
        String cs = CompactSerialization.serialize("one", "two", "three", "four");
        assertEquals("one.two.three.four", cs);
    }

    public void testSerialize3() throws JoseException
    {
        String cs = CompactSerialization.serialize("one", "two", "three", null);
        assertEquals("one.two.three.", cs);
    }

    public void testSerialize4() throws JoseException
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
        catch (JoseException e)
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
        catch (JoseException e)
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
        catch (JoseException e)
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
        catch (JoseException e)
        {
        }
    }

}
