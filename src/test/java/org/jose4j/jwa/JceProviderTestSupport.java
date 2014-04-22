package org.jose4j.jwa;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

/**
 *
 */
public class JceProviderTestSupport
{
    boolean doReinitialize = true;

    private void reinitialize()
    {
        AlgorithmFactoryFactory.getInstance().reinitialize();
    }

    public void runWithBouncyCastleProvider(RunnableTest test) throws Exception
    {
        BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
        boolean hasBouncyCastleAlready = Security.getProvider(bouncyCastleProvider.getName()) != null;

        try
        {
            if (!hasBouncyCastleAlready)
            {
                Security.addProvider(bouncyCastleProvider);
                if (doReinitialize)
                {
                    reinitialize();
                }
            }

            test.runTest();
        }
        finally
        {
            if (!hasBouncyCastleAlready)
            {
                Security.removeProvider(bouncyCastleProvider.getName());
                if (doReinitialize)
                {
                    reinitialize();
                }
            }
        }
    }

    public void setDoReinitialize(boolean doReinitialize)
    {
        this.doReinitialize = doReinitialize;
    }

    public static interface RunnableTest
    {
        public abstract void runTest() throws Exception;
    }
}
