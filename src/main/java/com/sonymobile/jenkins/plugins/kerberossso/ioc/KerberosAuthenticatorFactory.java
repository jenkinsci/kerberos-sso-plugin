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

import javax.security.auth.login.LoginException;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.PrivilegedActionException;
import java.util.Map;

/**
 * Factory method pattern used to create KerberosAuthenticators.
 * @author Robert Sandell &lt;robert.sandell@sonymobile.com&gt;
 */
public interface KerberosAuthenticatorFactory {

    /**
     * Returns an instance of a KerberosAuthenticator object.
     * @param config the config the authenticator should have.
     * @return an instance of a KerberosAuthenticator object.
     * @throws LoginException if login goes wrong.
     * @throws IOException if the authentication fails.
     * @throws URISyntaxException if something goes wrong.
     * @throws PrivilegedActionException if something goes wrong.
     */
    KerberosAuthenticator getInstance(Map<String, String> config)
            throws LoginException, IOException, URISyntaxException, PrivilegedActionException;
}
