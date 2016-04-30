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


package org.jose4j.lang;

/**
 *
 */
public class ExceptionHelp
{
    public static String toStringWithCauses(Throwable t)
    {
        StringBuilder sb = new StringBuilder();
        sb.append(t);
        while (t.getCause() != null)
        {
            t = t.getCause();
            sb.append("; caused by: ").append(t);
        }
        return sb.toString();
    }

    public static String toStringWithCausesAndAbbreviatedStack(Throwable t, Class stopAt)
    {
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        while (t != null)
        {
            if (!first)
            {
                sb.append("; caused by: ");
            }

            sb.append(t).append(" at ");

            for (StackTraceElement ste : t.getStackTrace())
            {
                if (ste.getClassName().equals(stopAt.getName()))
                {
                    sb.append("...omitted...");
                    break;
                }
                sb.append(ste).append("; ");
            }

            t = t.getCause();
            first = false;
        }

        return sb.toString();
    }
}
