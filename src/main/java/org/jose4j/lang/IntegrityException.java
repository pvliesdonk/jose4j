package org.jose4j.lang;

/**
 */
public class IntegrityException extends JoseException
{
    public IntegrityException(String message)
    {
        super(message);
    }

    public IntegrityException(String message, Throwable cause)
    {
        super(message, cause);
    }
}
