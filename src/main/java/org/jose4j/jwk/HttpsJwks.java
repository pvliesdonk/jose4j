/*
 * Copyright 2012-2016 Brian Campbell
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

import org.jose4j.http.Get;
import org.jose4j.http.SimpleGet;
import org.jose4j.http.SimpleResponse;
import org.jose4j.lang.ExceptionHelp;
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Collections;
import java.util.Date;
import java.util.List;

/**
 * Represents a set of JSON Web Keys (typically public keys) published at an HTTPS URI.
 * Keys will be retrieved from the given location and cached based on the cache directive
 * headers and/or the {@link #setDefaultCacheDuration(long)}.
 * The keys are cached per {@code HttpsJwks} instance so your application will need to keep using
 * the same instance, however is appropriate for that application, to get the benefit of the caching.
 * This class, when used with {@code HttpsJwksVerificationKeyResolver} can help facilitate the consuming side of
 * a key publication and rotation model like that which is described
 * in <a href="http://openid.net/specs/openid-connect-core-1_0.html#SigEnc">OpenID Connect, section 10</a>.
 *
 * @see org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver
 */
public class HttpsJwks
{
    private static final Logger log = LoggerFactory.getLogger(HttpsJwks.class);

    private String location;
    private long defaultCacheDuration = 3600;  // seconds
    private SimpleGet simpleHttpGet = new Get();
    private long retainCacheOnErrorDurationMills = 0;

    private Cache cache = new Cache(Collections.<JsonWebKey>emptyList(), 0);

    /**
     * Create a new HttpsJwks that cab be used to retrieve JWKs from the given location.
     * @param location the HTTPS URI of the JSON Web Key Set
     */
    public HttpsJwks(String location)
    {
        this.location = location;
    }

    /**
     * The time period to cache the JWKs from the endpoint, if the cache directive
     * headers of the response are not present or indicate that the content should not be cached.
     * This is useful because the content of a JWKS endpoint should be cached in the vast majority
     * of situations and cache directive headers that indicate otherwise are likely a mistake or
     * misconfiguration.
     *
     * The default value, used when this method is not called, of the default cache duration is 3600 seconds (1 hour).
     *
     * @param defaultCacheDuration the length in seconds of the default cache duration
     */
    public void setDefaultCacheDuration(long defaultCacheDuration)
    {
        this.defaultCacheDuration = defaultCacheDuration;
    }

    /**
     * Sets the length of time, before trying again, to keep using the cache when an error occurs making the request to
     * the JWKS URI or parsing the response. When equal or less than zero, an exception will be thrown from {@link #getJsonWebKeys()}
     * when an error occurs. When larger than zero, the previously established cached list of keys (if it exists) will be used/returned
     * and another attempt to fetch the keys from the JWKS URI will not be made for the given duration.
     * The default value is 0.
     * @param retainCacheOnErrorDuration the length in seconds to keep using the cache when an error occurs before trying again
     */
    public void setRetainCacheOnErrorDuration(long retainCacheOnErrorDuration)
    {
        this.retainCacheOnErrorDurationMills = retainCacheOnErrorDuration * 1000L;
    }

    /**
     * Sets the SimpleGet instance to use when making the HTTP GET request to the JWKS location.
     * By default a new instance of {@link org.jose4j.http.Get} is used. This method should be used
     * right after construction, if a different implementation of {@link org.jose4j.http.SimpleGet}
     * or non-default configured instance of {@link org.jose4j.http.Get} is needed.
     * @param simpleHttpGet the instance of the implementation of SimpleGet to use
     */
    public void setSimpleHttpGet(SimpleGet simpleHttpGet)
    {
        this.simpleHttpGet = simpleHttpGet;
    }

    /**
     * Gets the location of the JWKS endpoint/URL.
     * @return the location
     */
    public String getLocation()
    {
        return location;
    }

    /**
     * Gets the JSON Web Keys from the JWKS endpoint location or from local cache, if appropriate.
     * @return a list of JsonWebKeys
     * @throws JoseException if an problem is encountered parsing the JSON content into JSON Web Keys.
     * @throws IOException if a problem is encountered making the HTTP request.
     */
    public List<JsonWebKey> getJsonWebKeys() throws JoseException, IOException
    {
        final long now = System.currentTimeMillis();
        if (cache.getExp() < now)
        {
            try
            {
                refresh();
            }
            catch (Exception e)
            {
                if (retainCacheOnErrorDurationMills > 0 && !cache.keys.isEmpty())
                {
                    cache.exp = now + (retainCacheOnErrorDurationMills);
                    log.info("Because of {} unable to refersh JWKS content from {} so will continue to use cached keys for more {} seconds until about {} -> {}", ExceptionHelp.toStringWithCauses(e), location, retainCacheOnErrorDurationMills/1000L, new Date(cache.exp), cache.keys);
                }
                else
                {
                    throw e;
                }
            }
        }
        return cache.getKeys();
    }


    /**
     * Forces a refresh of the cached JWKs from the JWKS endpoint.
     * @throws JoseException if an problem is encountered parsing the JSON content into JSON Web Keys.
     * @throws IOException if a problem is encountered making the HTTP request.
     */
    public void refresh() throws JoseException, IOException
    {
        log.debug("Refreshing/loading JWKS from {}", location);
        SimpleResponse simpleResponse = simpleHttpGet.get(location);
        JsonWebKeySet jwks = new JsonWebKeySet(simpleResponse.getBody());
        List<JsonWebKey> keys = jwks.getJsonWebKeys();
        long cacheLife = getCacheLife(simpleResponse);
        if (cacheLife <= 0)
        {
            log.debug("Will use default cache duration of {} seconds for content from {}", defaultCacheDuration, location);
            cacheLife = defaultCacheDuration;
        }
        long exp = System.currentTimeMillis() + (cacheLife * 1000L);
        log.debug("Updated JWKS content from {} will be cached for {} seconds until about {} -> {}", location, cacheLife, new Date(exp), keys);
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
