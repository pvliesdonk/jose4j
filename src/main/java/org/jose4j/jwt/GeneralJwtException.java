package org.jose4j.jwt;

/**
 *
 */
public class GeneralJwtException extends Exception
{
    public GeneralJwtException(String message)
    {
        super(message);
    }

    public GeneralJwtException(String message, Throwable cause)
    {
        super(message, cause);
    }
}
