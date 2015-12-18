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
package org.jose4j.jwe;

import org.jose4j.jca.ProviderContext;
import org.jose4j.jwx.Headers;

import static org.jose4j.jwe.KeyManagementAlgorithmIdentifiers.DIRECT;
import static org.jose4j.jwx.HeaderParameterNames.ALGORITHM;

/**
 *
 */
class ContentEncryptionHelp
{
    static String getCipherProvider(Headers headers, ProviderContext providerCtx)
    {
        ProviderContext.Context ctx = choseContext(headers, providerCtx);
        return ctx.getCipherProvider();
    }

    static String getMacProvider(Headers headers, ProviderContext providerContext)
    {
        ProviderContext.Context ctx = choseContext(headers, providerContext);
        return ctx.getMacProvider();
    }

    private static ProviderContext.Context choseContext(Headers headers, ProviderContext providerCtx)
    {
        boolean isDir = headers != null && DIRECT.equals(headers.getStringHeaderValue(ALGORITHM));
        return isDir ? providerCtx.getSuppliedKeyProviderContext() : providerCtx.getGeneralProviderContext();
    }
}
