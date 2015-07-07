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

package org.jose4j.jwa;

import org.jose4j.lang.ExceptionHelp;
import org.jose4j.lang.InvalidAlgorithmException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 */
public class AlgorithmFactory<A extends Algorithm>
{
    private final Logger log;

    private String parameterName;

    private final Map<String,A> algorithms = new LinkedHashMap<>();

    public AlgorithmFactory(String parameterName, Class<A> type)
    {
        this.parameterName = parameterName;
        this.log = LoggerFactory.getLogger(getClass() + "->" + type.getSimpleName());
    }

    public A getAlgorithm(String algorithmIdentifier) throws InvalidAlgorithmException
    {
        A algo = algorithms.get(algorithmIdentifier);

        if (algo == null)
        {
            throw new InvalidAlgorithmException(algorithmIdentifier + " is an unknown, unsupported or unavailable "+parameterName
                    +" algorithm (not one of " + getSupportedAlgorithms() + ").");
        }
        
        return algo;
    }

    public boolean isAvailable(String algorithmIdentifier)
    {
        return algorithms.containsKey(algorithmIdentifier);
    }

    public Set<String> getSupportedAlgorithms()
    {
        return Collections.unmodifiableSet(algorithms.keySet());
    }

    public void registerAlgorithm(A algorithm)
    {
        String algId = algorithm.getAlgorithmIdentifier();
        if (isAvailable(algorithm))
        {
            algorithms.put(algId, algorithm);
            log.info("{} registered for {} algorithm {}", algorithm, parameterName, algId);
        }
        else
        {
            log.info("{} is unavailable so will not be registered for {} algorithms.", algId, parameterName);
        }
    }

    private boolean isAvailable(A algorithm)
    {
        try
        {
            return algorithm.isAvailable();
        }
        catch (Throwable e)
        {
            log.debug("Unexpected problem checking for availability of " +algorithm.getAlgorithmIdentifier()+ " algorithm: " + ExceptionHelp.toStringWithCauses(e));
            return false;
        }
    }


    public void unregisterAlgorithm(String algorithmIdentifier)
    {
        algorithms.remove(algorithmIdentifier);
    }
}
