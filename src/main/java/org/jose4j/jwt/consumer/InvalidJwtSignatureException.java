package org.jose4j.jwt.consumer;

/**
 *
 */
public class InvalidJwtSignatureException extends InvalidJwtException
{
    public InvalidJwtSignatureException(String message)
    {
        super(message);
    }
}
