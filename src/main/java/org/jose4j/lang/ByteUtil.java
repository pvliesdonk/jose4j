package org.jose4j.lang;


import java.nio.ByteBuffer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class ByteUtil
{
    public static final byte[] EMPTY_BYTES = new byte[0];

    public static byte[] convertUnsignedToSignedTwosComp(int[] ints)
    {
        byte[] bytes = new byte[ints.length];
        for (int idx = 0; idx < ints.length; idx++)
        {
            bytes[idx] = ByteUtil.getByte(ints[idx]);
        }
        return bytes;
    }

    public static int[] convertSignedTwosCompToUnsigned(byte[] bytes)
    {
        int[] ints = new int[bytes.length];
        for (int idx = 0; idx < bytes.length; idx++)
        {
            ints[idx] = ByteUtil.getInt(bytes[idx]);
        }
        return ints;
    }

    public static byte getByte(int intValue)
    {
        byte[] bytes = getBytes(intValue);
        if (bytes[0] != 0 || bytes[1] != 0 || bytes[2] != 0)
        {
            throw new IllegalArgumentException("Integer value (" + intValue + ") too large to stuff into one byte.");
        }
        return bytes[3];
    }

    public static byte[] getBytes(int intValue)
    {
        ByteBuffer byteBuffer = ByteBuffer.allocate(4);
        byteBuffer.putInt(intValue);
        return byteBuffer.array();
    }

    public static int getInt(byte b)
    {
        return (b >= 0) ? (int) b : 256 - (~(b - 1));
    }

    public static boolean secureEquals(byte[] bytes1, byte[] bytes2)
    {
        bytes1 = (bytes1 == null) ? EMPTY_BYTES : bytes1;
        bytes2 = (bytes2 == null) ? EMPTY_BYTES : bytes2;

        int shortest = Math.min(bytes1.length, bytes2.length);
        int longest = Math.max(bytes1.length, bytes2.length);

        int result = 0;

        // should be a time-constant comparison with respect to the length
        for (int i = 0; i < shortest; i++)
        {
            result |= bytes1[i] ^ bytes2[i];
        }

        return (result == 0) && (shortest == longest) ;
    }

    public static byte[] concat(byte[]... byteArrays)
    {
        try
        {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            for (byte[] bytes : byteArrays)
            {
                byteArrayOutputStream.write(bytes);
            }
            return byteArrayOutputStream.toByteArray();
        }
        catch (IOException e)
        {
            throw new IllegalStateException("IOEx from ByteArrayOutputStream?!", e);
        }
    }
}
