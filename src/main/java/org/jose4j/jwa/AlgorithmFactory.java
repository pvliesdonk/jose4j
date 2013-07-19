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

package org.jose4j.jwa;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.lang.JoseException;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.*;

/**
 */
public class AlgorithmFactory<A extends Algorithm>
{
    private final Log log = LogFactory.getLog(this.getClass());
    
    private static final String BASE_PATH = "META-INF/org.jose4j/";

    private final Map<String,A> algorithms = new HashMap<String,A>();
    
    AlgorithmFactory(String resourceName)
    {
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();

        try
        {
            String resource = BASE_PATH + resourceName;
            for (Enumeration<URL> enumeration = classLoader.getResources(resource); enumeration.hasMoreElements(); )
            {
                URL url = enumeration.nextElement();
                processPropsFile(url);
            }
        }
        catch (IOException e)
        {
            log.error("Could not load algorithm implementations from " + resourceName, e);
        }

    }

    private void processPropsFile(URL url)
    {
        try
        {
            Object contentObj = url.getContent();
            Properties props = new Properties();
            props.load((InputStream)contentObj);
            log.debug("loading algorithm implementation class names: " + props);

            for (String key : props.stringPropertyNames())
            {
                addAlgorithm(props, key);
            }
        }
        catch (IOException e)
        {
            log.error("Could not load algorithm implementations from " + url, e);
        }
    }

    private void addAlgorithm(Properties props, String key)
    {
        String className = props.getProperty(key);
        try
        {
            A algorithm = createClass(className);
            algorithms.put(key, algorithm);
            log.info("Loaded " + algorithm.getClass() + " implementation for " + key);
        }
        catch (Exception e)
        {
            log.error("Unable to create instance of " + className + " for " + key, e);
        }
    }
    
    @SuppressWarnings("unchecked")
    private A createClass(String className) throws ClassNotFoundException, InstantiationException, IllegalAccessException
    {
        Class<?> daClass = Class.forName(className);
        return (A) daClass.newInstance();
    }

    public A getAlgorithm(String algorithmIdentifier) throws JoseException
    {
        A algo = algorithms.get(algorithmIdentifier);
        
        if (algo == null)
        {
            throw new JoseException(algorithmIdentifier + " is an unknown or unsupported algorithm (not one of " + getSupportedAlgorithms() + ").");
        }
        
        return algo;
    }

    public Set<String> getSupportedAlgorithms()
    {
        return Collections.unmodifiableSet(algorithms.keySet());
    }
}
