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
package org.jose4j.jwa;

import java.security.Security;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 */
public class AlgorithmAvailability
{
    private static Logger log = LoggerFactory.getLogger(AlgorithmAvailability.class);

    public static boolean isAvailable(String serviceName, String algorithm)
    {
        Set<String> algorithms = Security.getAlgorithms(serviceName);
        for (String serviceAlg : algorithms)
        {
            if (serviceAlg.equalsIgnoreCase(algorithm))
            {
                return true;
            }
        }

        log.debug("{} is NOT available for {}. Algorithms available from underlying JCE: {}", algorithm, serviceName, algorithms);
        return false;
    }
}
