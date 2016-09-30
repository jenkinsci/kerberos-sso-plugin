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

package com.sonymobile.jenkins.plugins.kerberossso;

import com.sonymobile.jenkins.plugins.kerberossso.ioc.KerberosAuthenticator;
import com.sonymobile.jenkins.plugins.kerberossso.ioc.KerberosAuthenticatorFactory;
import hudson.Functions;
import hudson.security.ACL;
import hudson.security.SecurityRealm;
import jenkins.model.Jenkins;
import jenkins.security.SecurityListener;
import org.codelibs.spnego.SpnegoHttpServletResponse;
import org.acegisecurity.Authentication;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.springframework.dao.DataAccessException;

import javax.security.auth.login.LoginException;
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
import java.security.Principal;
import java.util.Collections;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Filter that authenticates users using Kerberos SSO.
 * @author Joakim Ahle &lt;joakim.ahle@sonymobile.com&gt;
 * @author Fredrik Persson &lt;fredrik6.persson@sonymobile.com&gt;
 */
public class KerberosSSOFilter implements Filter {

    /**
     * Header name that can be passed in a request in order to make this
     * filter ignore the request and just pass it on in the filter chain.
     */
    public static final String BYPASS_HEADER = "Bypass-Kerberos";

    private static final Logger logger = Logger.getLogger(KerberosSSOFilter.class.getName());

    /*package for testing*/ final transient Map<String, String> config;

    /** Nonnull until initialized */
    private KerberosAuthenticatorFactory authenticatorFactory;
    /** Nonnull after initialized and before destroyed */
    private KerberosAuthenticator authenticator;

    /**
     * Saves the submitted config. The filter will then be started when init is called.
     * @param config the filter configuration
     * @param authenticatorFactory the factory used to create the desired authenticator type
     *                             in the init method.
     */
    public KerberosSSOFilter(Map<String, String> config, KerberosAuthenticatorFactory authenticatorFactory) {
        this.config = Collections.unmodifiableMap(config);
        this.authenticatorFactory = authenticatorFactory;
    }

    /**
     * Creates the spnego authenticator to be used in doFilter.
     * @param filterConfig ignored.
     * @throws ServletException if the SpnegoAuthenticator can't be created. (Something is wrong in the config)
     */
    public void init(FilterConfig filterConfig) throws ServletException {
        logger.info("Kerberos filter initiated");
        try {
            authenticator = authenticatorFactory.getInstance(config);
        } catch (Exception e) {
            // Jenkins does not report stacktrace here in error.jelly
            // TODO remove after https://github.com/jenkinsci/jenkins/pull/2555
            logger.log(Level.WARNING, "Unable to initialize " + getClass().getSimpleName(), e);
            throw new ServletException(e);
        }
        authenticatorFactory = null;
    }

    /**
     * The filter is used by the container.
     *
     * @return true if used by servlet container.
     */
    /*package*/ boolean isActive() {
        return authenticator != null && authenticatorFactory == null;
    }

    /**
     * Filters every request made to the server to determine and set authentication of the user.
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

        if (!(request instanceof HttpServletRequest && response instanceof  HttpServletResponse)) {
            chain.doFilter(request, response);
            return;
        }

        HttpServletRequest httpRequest = (HttpServletRequest)request;
        if (containsBypassHeader(httpRequest) || !containsLoginURL(httpRequest)) {
            chain.doFilter(request, response);
            return;
        }

        String userContentPath = httpRequest.getContextPath() + "/userContent";
        if (httpRequest.getRequestURI().startsWith(userContentPath)) {
            chain.doFilter(request, response);
            return;
        }

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
                logger.fine("Redirecting request to " + redirect);
                spnegoHttpResponse.sendRedirect(redirect);
            }
        }

        // A user is "always" authenticated by Jenkins as anonymous when not authenticated in any other way.
        if (SecurityContextHolder.getContext().getAuthentication() == null
                || !SecurityContextHolder.getContext().getAuthentication().isAuthenticated()
                || Functions.isAnonymous()) {
            Functions.advertiseHeaders((HttpServletResponse)response); //Adds headers for CLI

            Principal principal;

            try {
                logger.fine("Authenticating request");
                principal = authenticator.authenticate(httpRequest, spnegoHttpResponse);
                if (principal != null) {
                    logger.log(Level.FINE, "Authenticated principal {0}", principal.getName());
                }
            } catch (LoginException e) {
                logger.log(Level.WARNING, "Failed to fetch spnegoPrincipal name for user");
                chain.doFilter(request, spnegoHttpResponse);
                return;
            }

            if (principal == null) {
                logger.fine("Expecting negotiation");
                return;
            }

            String principalName = principal.getName();

            if (principalName.contains("@")) {
                principalName = principalName.substring(0, principalName.indexOf("@"));
            }

            try {
                SecurityRealm realm = Jenkins.getInstance().getSecurityRealm();
                UserDetails userDetails = realm.loadUserByUsername(principalName);
                String username = userDetails.getUsername();
                Authentication authToken = new UsernamePasswordAuthenticationToken(
                        username,
                        userDetails.getPassword(),
                        userDetails.getAuthorities());

                ACL.impersonate(authToken);
                SecurityListener.fireLoggedIn(username);
                logger.log(Level.FINE, "Authenticated user {0}", username);
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
     * Checks if request contains a URL for which we should attempt a login.
     *
     * @param request the request to check for URL in
     * @return true if the request contained a login URL, otherwise false
     */
    private static boolean containsLoginURL(HttpServletRequest request) {
        /* If the user has directed us to log in for all URLs, then return true. */
        if (PluginImpl.getInstance().getLoginAllURLs()) {
            return true;
        }

        return "/login".equals(request.getPathInfo());
    }

    /**
     * Checks if request contains a bypass header.
     *
     * @param request the request to check for header in
     * @return true if the request contained a bypass header, otherwise false
     */
    private static boolean containsBypassHeader(HttpServletRequest request) {
        return request.getHeader(BYPASS_HEADER) != null;
    }

    /**
     * Called if the filter needs to be destroyed.
     */
    public void destroy() {
        if (authenticator != null) {
            authenticator.dispose();
        }
    }
}
