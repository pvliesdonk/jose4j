package org.jose4j.jwa;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.security.Security;
import java.util.Set;

/**
 */
public class AlgorithmAvailability
{
    private static Log log = LogFactory.getLog(AlgorithmAvailability.class);

    public static boolean isAvailable(String serviceName, String algorithm)
    {
        Set<String> algorithms = Security.getAlgorithms(serviceName);
        for (String signatureAlgorithm : algorithms)
        {
            if (signatureAlgorithm.equalsIgnoreCase(algorithm))
            {
                return true;
            }
        }

        log.info(algorithm + " is NOT available for " + serviceName +
                    ". Algorithms available from underlying JCE: " + algorithms);
        return false;
    }
}
