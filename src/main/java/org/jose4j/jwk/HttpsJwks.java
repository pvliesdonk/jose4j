/*
 * Copyright 2012-2015 Brian Campbell
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jose4j.jwk;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.http.Get;
import org.jose4j.http.SimpleGet;
import org.jose4j.http.SimpleResponse;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.UncheckedJoseException;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;
import java.util.Date;
import java.util.List;

/**
 *
 */
public class HttpsJwks
{
    private static Log log = LogFactory.getLog(HttpsJwks.class);

    private URL location;
    private long defaultCacheDuration = 3600;
    private SimpleGet simpleHttpGet = new Get();

    private Cache cache = new Cache(Collections.<JsonWebKey>emptyList(), 0);

    public HttpsJwks(String location)
    {
        try
        {
            this.location = new URL(location);
        }
        catch (MalformedURLException e)
        {
            throw new UncheckedJoseException("The location of the HTTPS JWKS endpoint ("+location+") could not be parsed into a URL.", e);
        }
    }

    public void setDefaultCacheDuration(long defaultCacheDuration)
    {
        this.defaultCacheDuration = defaultCacheDuration;
    }

    public void setSimpleHttpGet(SimpleGet simpleHttpGet)
    {
        this.simpleHttpGet = simpleHttpGet;
    }

    public URL getLocation()
    {
        return location;
    }

    public List<JsonWebKey> getJsonWebKeys() throws JoseException, IOException
    {
        if (cache.getExp() < System.currentTimeMillis())
        {
            refresh();
        }
        return cache.getKeys();
    }

    public void refresh() throws JoseException, IOException
    {
        if (log.isDebugEnabled()) {log.debug("Refreshing/loading JWKS from " + location);}
        SimpleResponse simpleResponse = simpleHttpGet.get(location);
        JsonWebKeySet jwks = new JsonWebKeySet(simpleResponse.getBody());
        List<JsonWebKey> keys = jwks.getJsonWebKeys();
        long cacheLife = getCacheLife(simpleResponse);
        if (cacheLife <= 0)
        {
            if (log.isDebugEnabled()) {log.debug("Will use default cache duration of "+defaultCacheDuration+" seconds for content from " + location);}
            cacheLife = defaultCacheDuration;
        }
        long exp = System.currentTimeMillis() + (cacheLife * 1000L);
        if (log.isDebugEnabled()) {log.debug("Updated JWKS content from " + location + " will be cached for " + cacheLife + " seconds until " + new Date(exp) + " -> " + keys);}
        cache = new Cache(keys, exp);
    }

    static long getDateHeaderValue(SimpleResponse response, String headerName, long defaultValue)
    {
        List<String> values = getHeaderValues(response, headerName);
        for (String value : values)
        {
            try
            {
                if (!value.endsWith("GMT"))
                {
                    value += " GMT";
                }

                return Date.parse(value);
            }
            catch (Exception e)
            {
                // ignore it
            }
        }
        return defaultValue;
    }

    private static List<String> getHeaderValues(SimpleResponse response, String headerName)
    {
        List<String> values = response.getHeaderValues(headerName);
        return  (values == null) ? Collections.<String>emptyList() : values;
    }

    static long getExpires(SimpleResponse response)
    {
        return getDateHeaderValue(response, "expires", 0);
    }

    static long getCacheLife(SimpleResponse response)
    {
        return getCacheLife(response, System.currentTimeMillis());
    }

    static long getCacheLife(SimpleResponse response, long currentTime)
    {
        // start with expires
        long expires = getExpires(response);
        long life = (expires - currentTime) / 1000L;

        // but Cache-Control takes precedence
        List<String> values = getHeaderValues(response, "cache-control");
        for (String value : values)
        {
            try
            {
                // only care about the max-age value so just pull it out rather than parsing the whole header
                value = (value == null) ? "" : value.toLowerCase();
                int indexOfMaxAge = value.indexOf("max-age");
                int indexOfComma = value.indexOf(',', indexOfMaxAge);
                int end = indexOfComma == -1 ? value.length() : indexOfComma;
                String part = value.substring(indexOfMaxAge, end);
                part = part.substring(part.indexOf('=') + 1);
                part = part.trim();
                life = Long.parseLong(part);
                break;
            }
            catch (Exception e)
            {
                // ignore it
            }

        }

        return life;
    }

    private static class Cache
    {
        private List<JsonWebKey> keys;
        private long exp;

        private Cache(List<JsonWebKey> keys, long exp)
        {
            this.keys = keys;
            this.exp = exp;
        }

        private List<JsonWebKey> getKeys()
        {
            return keys;
        }

        private long getExp()
        {
            return exp;
        }
    }
}
