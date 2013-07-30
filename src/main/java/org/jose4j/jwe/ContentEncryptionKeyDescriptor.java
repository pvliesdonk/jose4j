package org.jose4j.jwe;

/**
 */
public class ContentEncryptionKeyDescriptor
{
    private final int contentEncryptionKeyByteLength;
    private final String ContentEncryptionKeyAlgorithm;

    public ContentEncryptionKeyDescriptor(int contentEncryptionKeyByteLength, String contentEncryptionKeyAlgorithm)
    {
        this.contentEncryptionKeyByteLength = contentEncryptionKeyByteLength;
        ContentEncryptionKeyAlgorithm = contentEncryptionKeyAlgorithm;
    }

    /**
     * Gets the key size in bytes.
     *
     * @return the length, in bytes, of the key used by this algorithm
     */
    public int getContentEncryptionKeyByteLength()
    {
        return contentEncryptionKeyByteLength;
    }

    public String getContentEncryptionKeyAlgorithm()
    {
        return ContentEncryptionKeyAlgorithm;
    }
}
