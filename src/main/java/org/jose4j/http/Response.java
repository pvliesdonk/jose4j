package org.jose4j.http;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 *
 */
public class Response implements SimpleResponse
{
    private int statusCode;
    private String statusMessage;
    private Map<String, List<String>> headers;
    private String body;

    public Response(int statusCode, String statusMessage, Map<String, List<String>> headers, String body)
    {
        this.statusCode = statusCode;
        this.statusMessage = statusMessage;
        this.headers = new HashMap<>();
        for (Map.Entry<String,List<String>> header : headers.entrySet())
        {
            String name = normalizeHeaderName(header.getKey());
            this.headers.put(name, header.getValue());
        }
        this.body = body;
    }

    @Override
    public int getStatusCode()
    {
        return statusCode;
    }

    @Override
    public String getStatusMessage()
    {
        return statusMessage;
    }

    @Override
    public Collection<String> getHeaderNames()
    {
        return headers.keySet();
    }

    @Override
    public List<String> getHeaderValues(String name)
    {
        name = normalizeHeaderName(name);
        return headers.get(name);
    }

    @Override
    public String getBody()
    {
        return body;
    }

    private String normalizeHeaderName(String name)
    {
        return name != null ? name.toLowerCase().trim() : null;
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
