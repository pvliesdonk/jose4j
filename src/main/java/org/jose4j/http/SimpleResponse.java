package org.jose4j.http;

import java.util.List;
import java.util.Map;

/**
 *
 */
public class SimpleResponse
{
    private int statusCode;
    private String statusMessage;
    private Map<String, List<String>> headers;
    private String body;

    public SimpleResponse(int statusCode, String statusMessage, Map<String, List<String>> headers, String body)
    {
        this.statusCode = statusCode;
        this.statusMessage = statusMessage;
        this.headers = headers;
        this.body = body;
    }

    public int getStatusCode()
    {
        return statusCode;
    }

    public String getStatusMessage()
    {
        return statusMessage;
    }

    public Map<String, List<String>> getHeaders()
    {
        return headers;
    }

    public String getBody()
    {
        return body;
    }

    @Override
    public String toString()
    {
        return "SimpleResponse{" +
                "statusCode=" + statusCode +
                ", statusMessage='" + statusMessage + '\'' +
                ", headers=" + headers +
                ", body='" + body + '\'' +
                '}';
    }
}
