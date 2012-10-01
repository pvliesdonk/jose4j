package org.jose4j.jwa;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Enumeration;
import java.util.Properties;
import java.util.Map;
import java.util.HashMap;

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

    public A getAlgorithm(String algorithmIdentifier)
    {
        return algorithms.get(algorithmIdentifier);
    }
}
