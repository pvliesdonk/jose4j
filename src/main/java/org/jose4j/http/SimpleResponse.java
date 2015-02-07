package org.jose4j.http;

import java.util.Collection;
import java.util.List;

/**
 *
 */
public interface SimpleResponse
{
    int getStatusCode();

    String getStatusMessage();

    Collection<String> getHeaderNames();

    List<String> getHeaderValues(String name);

    String getBody();
}
