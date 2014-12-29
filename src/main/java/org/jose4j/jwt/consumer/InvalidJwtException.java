package org.jose4j.jwt.consumer;

import java.util.Collections;
import java.util.List;

/**
 *
 */
public class InvalidJwtException extends Exception
{
    private List<String> details = Collections.emptyList();

    public InvalidJwtException(String message)
    {
        super(message);
    }

    public InvalidJwtException(String message, Throwable cause)
    {
        super(message, cause);
    }

    public void setDetails(List<String> details)
    {
        this.details = details;
    }

    @Override
    public String getMessage()
    {
        StringBuilder sb = new StringBuilder();
        sb.append(super.getMessage());
        if (!details.isEmpty())
        {
            sb.append(" Additional details: ");
            sb.append(details);
        }
        return sb.toString();
    }
}
