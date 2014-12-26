package org.jose4j.jwt;

/**
 *
 */
public class MalformedClaimException extends JwtException
{
    public MalformedClaimException(String message)
    {
        super(message);
    }

    public MalformedClaimException(String message, Throwable cause)
    {
        super(message, cause);
    }
}
