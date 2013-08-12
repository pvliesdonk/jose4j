package org.jose4j.zip;

import org.jose4j.lang.JoseException;
import org.jose4j.lang.UncheckedJoseException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

/**
 */
public class DeflateRFC1951
{
    public static byte[] compress(byte[] data)
    {
        Deflater deflater = new Deflater(Deflater.DEFLATED, true);
        try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
             DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream, deflater))
        {
            deflaterOutputStream.write(data);
            deflaterOutputStream.finish();
            return byteArrayOutputStream.toByteArray();
        }
        catch (IOException e)
        {
            throw new UncheckedJoseException("Problem compressing data.", e);
        }
    }

    public static byte[] decompress(byte[] compressedData) throws JoseException
    {
        Inflater inflater = new Inflater(true);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        try (InflaterInputStream iis = new InflaterInputStream(new ByteArrayInputStream(compressedData), inflater))
        {
            int bytesRead;
            byte[] buff = new byte[256];
            while ((bytesRead = iis.read(buff)) != -1)
            {
                byteArrayOutputStream.write(buff, 0, bytesRead);
            }

            return byteArrayOutputStream.toByteArray();
        }
        catch (IOException e)
        {
            throw new JoseException("Problem compressing data.", e);
        }
    }
}
