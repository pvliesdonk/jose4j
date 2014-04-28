/*
 * Copyright 2012-2013 Brian Campbell
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

package com.notsure;

import java.security.Provider;
import java.security.Security;

/**
 * Just a sandbox for messing with stuff
 */
public class App 
{
    public static void main(String... meh) throws Exception
    {
        dumpProviderInfo();
    }

    public static void dumpProviderInfo()
    {
        String version = System.getProperty("java.version");
        String vendor = System.getProperty("java.vendor");
        String home = System.getProperty("java.home");
        System.out.println("Java "+version+" from "+vendor+" at "+home+"");
        for (Provider provider : Security.getProviders())
        {
            System.out.println("Provider: " + provider.getName());
            for (Provider.Service service : provider.getServices())
            {
                System.out.println(" -> Algorithm: " + service.getAlgorithm());
            }
        }
    }

}
