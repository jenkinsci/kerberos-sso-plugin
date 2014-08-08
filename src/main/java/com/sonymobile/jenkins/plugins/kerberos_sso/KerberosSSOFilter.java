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

package com.sonymobile.jenkins.plugins.kerberos_sso;

import hudson.Functions;
import hudson.security.SecurityRealm;
import jenkins.model.Jenkins;
import jenkins.security.NonSerializableSecurityContext;
import net.sourceforge.spnego.SpnegoAuthenticator;
import net.sourceforge.spnego.SpnegoHttpServletResponse;
import net.sourceforge.spnego.SpnegoPrincipal;
import org.acegisecurity.Authentication;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.springframework.dao.DataAccessException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Filter that authenticates users using Kerberos SSO.
 * @author Joakim Ahle &lt;joakim.ahle@sonyericsson.com&gt;
 * @author Fredrik Persson &lt;fredrik6.persson@sonyericsson.com&gt;
 */
public class KerberosSSOFilter implements Filter {

    private transient SpnegoAuthenticator spnegoAuthenticator;
    private static final Logger logger = Logger.getLogger(KerberosSSOFilter.class.getName());

    private transient Map<String, String> config = new HashMap<String, String>();

    /**
     * Saves the submitted config. The filter will then be started when init is called.
     * @param config the filter configuration
     */
    public KerberosSSOFilter(Map<String, String> config) {
        this.config = config;
    }

    /**
     * Creates the spnego authenticator to be used in doFilter.
     * @param filterConfig ignored.
     * @throws ServletException if the SpnegoAuthenticator can't be created. (Something is wrong in the config)
     */
    public void init(FilterConfig filterConfig) throws ServletException {
        try {
            spnegoAuthenticator = new SpnegoAuthenticator(config);
        } catch (Exception e) {
            throw new ServletException("Failed to initialize Kerberos SSO filter", e);
        }
    }

    /**
     * Filters every request made to the server do determine and set authentication of the user.
     * 1. Find out if the user is already authenticated (by checking the securityContext).
     * 2. Otherwise, authenticate the user from his Kerberos ticket and,
     * 3. Set him as authenticated by setting a new securityContext.
     * During the negotiation process used by Spnego, none of the filters after this one in the chain
     * will be allowed to execute.
     *
     * @param request the Servlet request to serve
     * @param response the Servlet response to serve
     * @param chain the filter chain determining which filter will execute after ours.
     * @throws IOException if redirection goes wrong or if another filter in the chain fails.
     * @throws ServletException if the authentication fails.
     */
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (!(request instanceof HttpServletRequest) || !(response instanceof  HttpServletResponse)) {
            return;
        }

        HttpServletRequest httpRequest = (HttpServletRequest)request;
        SpnegoHttpServletResponse spnegoHttpResponse = new SpnegoHttpServletResponse(
                (HttpServletResponse)response);

        if (PluginImpl.getInstance().isRedirectEnabled()
                && !httpRequest.getLocalAddr().equals(httpRequest.getRemoteAddr())) {
                // If Local and Remote address is the same, the user is Localhost and shouldn't be redirected.

            String requestedDomain = new URL(httpRequest.getRequestURL().toString()).getHost();
            String requestedURL = httpRequest.getRequestURL().toString();
            if (!requestedDomain.toLowerCase().contains(PluginImpl.getInstance().getRedirect().toLowerCase())) {

                String redirect = requestedURL.replaceFirst(
                        requestedDomain, requestedDomain + "." + PluginImpl.getInstance().getRedirect());
                spnegoHttpResponse.sendRedirect(redirect);
            }
        }

        // A user is "always" authenticated by Jenkins as anonymous when not authenticated in any other way.
        if (SecurityContextHolder.getContext().getAuthentication() == null
                || !SecurityContextHolder.getContext().getAuthentication().isAuthenticated()
                || Functions.isAnonymous()) {

            SpnegoPrincipal spnegoPrincipal;
            try {
                spnegoPrincipal = spnegoAuthenticator.authenticate(httpRequest, spnegoHttpResponse);
            } catch (Exception e) {
                throw new ServletException("Failed to authenticate user", e);
            }

            // Expecting negotiation
            if (spnegoHttpResponse.isStatusSet()) {
                return;
            }

            if (spnegoPrincipal == null) {
                logger.log(Level.WARNING, "Failed to fetch spnegoPrincipal name for user");
                chain.doFilter(request, spnegoHttpResponse);
                return;
            }

            String principalName = spnegoPrincipal.getName();

            if (principalName.contains("@")) {
                principalName = principalName.substring(0, principalName.indexOf("@"));
            }

            SecurityRealm realm = Jenkins.getInstance().getSecurityRealm();
            try {
                UserDetails userDetails = realm.loadUserByUsername(principalName);
                Authentication authToken = new UsernamePasswordAuthenticationToken(
                        userDetails.getUsername(),
                        userDetails.getPassword(),
                        userDetails.getAuthorities());

                SecurityContextHolder.setContext(new NonSerializableSecurityContext(authToken));
                logger.log(Level.FINE, "Authenticated user {0}", userDetails.getUsername());
            } catch (UsernameNotFoundException e) {
                logger.log(Level.WARNING, "Username {0} not registered by Jenkins", principalName);
            } catch (NullPointerException e) {
                logger.log(Level.WARNING, "User authentication failed");
                e.printStackTrace();
            } catch (DataAccessException e) {
                logger.log(Level.WARNING, "No access to user database");
                e.printStackTrace();
            }
        }

        chain.doFilter(request, response);
    }

    /**
     * Called if the filter needs to be destroyed.
     */
    public void destroy() {
        if (spnegoAuthenticator != null) {
            spnegoAuthenticator.dispose();
        }
    }
}
