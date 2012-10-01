package org.jose4j.jwe.kdf;

import org.jose4j.lang.StringUtil;
import org.jose4j.lang.ByteUtil;
import org.apache.commons.codec.CharEncoding;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 */
class ShaConcatKeyDerivationFunction
{
    private static final double MAX_REPS = Math.pow(2, 32) - 1;

    private int digestLenght;
    private String digestMethod;

    public static final byte[] ENCRYPTION_LABEL = StringUtil.getBytesUnchecked("Encryption", CharEncoding.US_ASCII);
    public static final byte[] INTEGRITY_LABEL = StringUtil.getBytesUnchecked("Integrity", CharEncoding.US_ASCII);

    public ShaConcatKeyDerivationFunction(int digestLenght)
    {
        this.digestLenght = digestLenght;
        this.digestMethod = "SHA-" + digestLenght;
    }

    public byte[] kdf(byte[] sharedSecret, int keydatalen, byte[] label)
    {
        long reps = getReps(keydatalen);
        MessageDigest digester = getDigester();

        byte[] derivedKeyingMaterial = new byte[0];

        for (int i = 1; i <= reps; i++)
        {
            byte[] counterBytes = ByteUtil.getBytes(i);
            byte[] input = ByteUtil.concat(counterBytes, sharedSecret, label);
            byte[] digest = digester.digest(input);

            derivedKeyingMaterial = ByteUtil.concat(derivedKeyingMaterial, digest); 
        }
                                                                                                            
        int keyDateLenInBytes = keydatalen / 8;
        if (derivedKeyingMaterial.length != keyDateLenInBytes)
        {
            byte[] newKeyMaterial = new byte[keyDateLenInBytes];
            System.arraycopy(derivedKeyingMaterial, 0, newKeyMaterial, 0, keyDateLenInBytes);
            derivedKeyingMaterial = newKeyMaterial;
        }

        return derivedKeyingMaterial;
    }

    private MessageDigest getDigester()
    {
        try
        {
           return MessageDigest.getInstance(digestMethod);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new IllegalStateException("Must have " + digestMethod, e);
        }
    }

    long getReps(int keydatalen)
    {
        double repsD = (float) keydatalen / (float) digestLenght;
        repsD = Math.ceil(repsD);
        long reps = Math.round(repsD);

        if (reps > MAX_REPS)
        {
            String msg = keydatalen + " key length gives reps > (2^32 - 1), so ABORTING: outputing an error indicator and stoping.";
            throw new IllegalArgumentException(msg);
        }

        return reps;
    }
}
