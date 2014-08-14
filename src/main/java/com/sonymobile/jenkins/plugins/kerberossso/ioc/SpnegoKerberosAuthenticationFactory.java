/*
 *  The MIT License
 *
 *  Copyright (c) 2014 Sony Mobile Communications Inc. All rights reserved.
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *  THE SOFTWARE.
 */

package com.sonymobile.jenkins.plugins.kerberossso.ioc;

import net.sourceforge.spnego.SpnegoAuthenticator;
import net.sourceforge.spnego.SpnegoHttpServletResponse;
import net.sourceforge.spnego.SpnegoPrincipal;
import org.ietf.jgss.GSSException;

import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.util.Map;

/**
 * Used to create SpnegoKerberosAuthenticators.
 * @author Robert Sandell &lt;robert.sandell@sonymobile.com&gt;
 */
public class SpnegoKerberosAuthenticationFactory implements KerberosAuthenticatorFactory {
    @Override
    public KerberosAuthenticator getInstance(final Map<String, String> config)
            throws LoginException, IOException, URISyntaxException, PrivilegedActionException {

        try {
            return new SpnegoKerberosAuthenticator(config);
        } catch (GSSException e) {
            throw new IOException(e);
        }
    }

    /**
     * This is the SpnegoKerberosAuthenticator mainly used outside test classes.
     * @author Robert Sandell &lt;robert.sandell@sonymobile.com&gt;
     */
    private static final class SpnegoKerberosAuthenticator implements KerberosAuthenticator {
        private final SpnegoAuthenticator spnegoAuthenticator;

        /**
         * Constructs a new SPNEGO authenticator from passed configuration.
         * @param config the configuration of the authenticator.
         * @throws LoginException if login goes wrong.
         * @throws FileNotFoundException if files specified by context is missing.
         * @throws URISyntaxException if something goes wrong.
         * @throws GSSException if authentication goes wrong.
         * @throws PrivilegedActionException if something goes wrong.
         */
        private SpnegoKerberosAuthenticator(Map<String, String> config)
                throws LoginException, FileNotFoundException, URISyntaxException,
                GSSException, PrivilegedActionException {

            spnegoAuthenticator = new SpnegoAuthenticator(config);
        }

        @Override
        public Principal authenticate(HttpServletRequest request, HttpServletResponse response)
                throws LoginException, IOException {

            SpnegoHttpServletResponse spRes = new SpnegoHttpServletResponse(response);
            SpnegoPrincipal principal = null;
            try {
                principal = spnegoAuthenticator.authenticate(request, spRes);
            } catch (GSSException e) {
                throw new IOException(e);
            }
            if (spRes.isStatusSet()) {
                return null;
            }
            if (principal == null) {
                throw new LoginException("Failed to fetch spnegoPrincipal name for user");
            }
            return principal;
        }

        @Override
        public void dispose() {
            spnegoAuthenticator.dispose();
        }
    }
}
