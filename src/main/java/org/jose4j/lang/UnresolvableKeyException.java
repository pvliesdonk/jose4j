package org.jose4j.lang;

/**
 *
 */
public class UnresolvableKeyException extends JoseException
{
    public UnresolvableKeyException(String message)
    {
        super(message);
    }

    public UnresolvableKeyException(String message, Throwable cause)
    {
        super(message, cause);
    }
}
