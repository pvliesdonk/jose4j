package org.jose4j.jwt.consumer;

import java.util.List;

/**
 *
 */
public class InvalidJwtException extends Exception
{
    List<String> details;

    public InvalidJwtException(String message)
    {
        super(message);
    }

    public InvalidJwtException(String message, Throwable cause)
    {
        super(message, cause);
    }
}
