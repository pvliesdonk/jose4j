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

import org.jose4j.http.Get;
import org.jose4j.http.Response;
import org.jose4j.http.SimpleResponse;
import org.jose4j.keys.X509Util;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;

/**
 *
 */
public class HttpsJwksTest
{
    private final Logger log = LoggerFactory.getLogger(this.getClass());

    @Test
    public void testExpiresDateHeadersPerRfc() throws Exception
    {
        /*
              3 different HTTP date formats per
              http://tools.ietf.org/html/rfc7231#section-7.1.1.1  or
              http://tools.ietf.org/html/rfc2616#section-3.3.1
              Sun, 06 Nov 1994 08:49:37 GMT  ; RFC 822, updated by RFC 1123
              Sunday, 06-Nov-94 08:49:37 GMT ; RFC 850, obsoleted by RFC 1036
              Sun Nov  6 08:49:37 1994       ; ANSI C's asctime() format
         */
        long actualDateMs = 784111777000L;
        long actualCacheLife = 60L;
        long fakeCurrentTime = 784111717000L;

        Map<String, List<String>> headers = Collections.singletonMap("Expires", Collections.singletonList("Sun, 06 Nov 1994 08:49:37 GMT"));
        SimpleResponse simpleResponse = new Response(200, "OK", headers, "doesn't matter");
        assertThat(actualDateMs, equalTo(HttpsJwks.getExpires(simpleResponse)));
        assertThat(actualCacheLife, equalTo(HttpsJwks.getCacheLife(simpleResponse, fakeCurrentTime)));

        headers = Collections.singletonMap("Expires", Collections.singletonList("Sunday, 06-Nov-94 08:49:37 GMT"));
        simpleResponse = new Response(200, "OK", headers, "doesn't matter");
        assertThat(actualDateMs, equalTo(HttpsJwks.getExpires(simpleResponse)));
        assertThat(actualCacheLife, equalTo(HttpsJwks.getCacheLife(simpleResponse, fakeCurrentTime)));

        headers = Collections.singletonMap("Expires", Collections.singletonList("Sun Nov  6 08:49:37 1994"));
        simpleResponse = new Response(200, "OK", headers, "*still* doesn't matter");
        assertThat(actualDateMs, equalTo(HttpsJwks.getExpires(simpleResponse)));
        assertThat(actualCacheLife, equalTo(HttpsJwks.getCacheLife(simpleResponse, fakeCurrentTime)));
    }

    @Test
    public void testCacheLifeFromCacheControlMaxAge() throws Exception
    {
        String[] headerValues =
        {
            "public, max-age=23760, must-revalidate, no-transform",
            "public, max-age=    23760 , must-revalidate",
            "public,max-age = 23760, must-revalidate",
            "public, max-age=23760, must-revalidate, no-transform",
            "must-revalidate,public,max-age=23760,no-transform",
            "max-age =23760, must-revalidate, public",
            "max-age=23760",
            "max-age =23760",
            "max-age = 23760 ",
            "max-age=23760,",
            "fake=\"f,a,k,e\",public, max-age=23760, must-revalidate=\"this , shouldn't be here\", whatever",
        };

        for (String headerValue : headerValues)
        {
            Map<String, List<String>> headers = new HashMap<>();
            headers.put("Expires", Collections.singletonList("Expires: Tue, 27 Jan 2015 16:00:10 GMT")); // Cache-Control takes precedence over this
            headers.put("Cache-Control", Collections.singletonList(headerValue));
            SimpleResponse simpleResponse = new Response(200, "OK", headers, "doesn't matter");
            long cacheLife = HttpsJwks.getCacheLife(simpleResponse);
            assertThat("it done broke on this one " + headerValue, 23760L , equalTo(cacheLife));
        }
    }

    // todo more tests

    @Test
    @Ignore // skip this one b/c of external dependency and manual intervention needed
    public void testKindaSimplisticConcurrent() throws Exception
    {
        X509Util x509Util = new X509Util();
        X509Certificate certificate = x509Util.fromBase64Der(
                "MIICUDCCAbkCBETczdcwDQYJKoZIhvcNAQEFBQAwbzELMAkGA1UEBhMCVVMxCzAJ\n" +
                "BgNVBAgTAkNPMQ8wDQYDVQQHEwZEZW52ZXIxFTATBgNVBAoTDFBpbmdJZGVudGl0\n" +
                "eTEXMBUGA1UECxMOQnJpYW4gQ2FtcGJlbGwxEjAQBgNVBAMTCWxvY2FsaG9zdDAe\n" +
                "Fw0wNjA4MTExODM1MDNaFw0zMzEyMjcxODM1MDNaMG8xCzAJBgNVBAYTAlVTMQsw\n" +
                "CQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRUwEwYDVQQKEwxQaW5nSWRlbnRp\n" +
                "dHkxFzAVBgNVBAsTDkJyaWFuIENhbXBiZWxsMRIwEAYDVQQDEwlsb2NhbGhvc3Qw\n" +
                "gZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJLrpeiY/Ai2gGFxNY8Tm/QSO8qg\n" +
                "POGKDMAT08QMyHRlxW8fpezfBTAtKcEsztPzwYTLWmf6opfJT+5N6cJKacxWchn/\n" +
                "dRrzV2BoNuz1uo7wlpRqwcaOoi6yHuopNuNO1ms1vmlv3POq5qzMe6c1LRGADyZh\n" +
                "i0KejDX6+jVaDiUTAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAMojbPEYJiIWgQzZc\n" +
                "QJCQeodtKSJl5+lA8MWBBFFyZmvZ6jUYglIQdLlc8Pu6JF2j/hZEeTI87z/DOT6U\n" +
                "uqZA83gZcy6re4wMnZvY2kWX9CsVWDCaZhnyhjBNYfhcOf0ZychoKShaEpTQ5UAG\n" +
                "wvYYcbqIWC04GAZYVsZxlPl9hoA=\n");


        String location = "https://localhost:9031/pf/JWKS";

        Get get = new Get();
        get.setTrustedCertificates(certificate);

        final HttpsJwks httpsJwks = new HttpsJwks(location);
        httpsJwks.setSimpleHttpGet(get);
        httpsJwks.setDefaultCacheDuration(1);
        httpsJwks.setRetainCacheOnErrorDuration(1);

        Callable<List> task = new Callable<List>()
        {
            @Override
            public List<JsonWebKey> call() throws Exception
            {
                List<JsonWebKey> jsonWebKeys = null;
                for (long i = 1000000000 ; i > 0 ; i--)
                {
                    jsonWebKeys = httpsJwks.getJsonWebKeys();
                    assertFalse(jsonWebKeys.isEmpty());
                    if (i % 10000000 == 0) { log.debug("... working ... " + i + " ... " + Thread.currentThread().toString());}
                }
                return jsonWebKeys;
            }
        };

        int threadCount = 5;
        ExecutorService executorService = Executors.newFixedThreadPool(threadCount);
        List<Callable<List>> tasks = Collections.nCopies(threadCount, task);

        List<Future<List>> futures = executorService.invokeAll(tasks);
        log.debug("=== and done ===");

        for (Future<List> future : futures)
        {
            log.debug(future.get().toString());
        }
    }
}
