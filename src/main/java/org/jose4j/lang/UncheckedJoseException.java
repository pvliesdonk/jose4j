package org.jose4j.lang;

/**
 */
public class UncheckedJoseException extends RuntimeException
{
    public UncheckedJoseException(String message)
    {
        super(message);
    }

    public UncheckedJoseException(String message, Throwable cause)
    {
        super(message, cause);
    }
}
