package org.jose4j.jwe;

/**
*/
public class ContentEncryptionKeys
{
    private final byte[] contentEncryptionKey;
    private final byte[] encryptedKey;

    public ContentEncryptionKeys(byte[] contentEncryptionKey, byte[] encryptedKey)
    {
        this.contentEncryptionKey = contentEncryptionKey;
        this.encryptedKey = encryptedKey;
    }

    public byte[] getContentEncryptionKey()
    {
        return contentEncryptionKey;
    }

    public byte[] getEncryptedKey()
    {
        return encryptedKey;
    }
}
