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
package org.jose4j.lang;

import java.security.Provider;
import java.security.Security;
import java.util.concurrent.atomic.AtomicBoolean;

public class ProviderHelp {
    private static final String BC_PROVIDER_FQCN = "org.bouncycastle.jce.provider.BouncyCastleProvider";
    
    private static final AtomicBoolean BC_LOADED = new AtomicBoolean(false);
    
    static 
    {
    	enableBouncyCastleProvider();
    }
    
    public static boolean isBouncyCastleAvailable() 
    {
    	return BC_LOADED.get();
    }

    public static void enableBouncyCastleProvider() 
    {
    	if (isBouncyCastleAvailable()) 
    	{
    		return;
    	}

    	try {
    		Class<Provider> bcProvider = (Class<Provider>) Class.forName(BC_PROVIDER_FQCN);

            for (Provider provider : Security.getProviders()) 
            {
                if (bcProvider.isInstance(provider)) 
                {
                	BC_LOADED.set(true);
                	break;
                }
            }
            
            if (!isBouncyCastleAvailable())
            {
        		Security.addProvider(bcProvider.newInstance());
        		BC_LOADED.set(true);
            }
    	} 
    	catch (Exception e)
    	{
    		// Not available...
    	}
    }
}
