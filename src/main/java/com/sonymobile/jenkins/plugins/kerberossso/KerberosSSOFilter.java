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
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Functions;
import hudson.Util;
import hudson.model.User;
import hudson.security.ACL;
import hudson.security.SecurityRealm;
import jenkins.model.Jenkins;
import jenkins.security.SecurityListener;
import jenkins.security.seed.UserSeedProperty;

import org.codelibs.spnego.SpnegoHttpServletResponse;
import org.kohsuke.accmod.restrictions.suppressions.SuppressRestrictedWarnings;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import javax.security.auth.login.LoginException;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.net.URL;
import java.security.Principal;
import java.util.Collections;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Filter that authenticates users using Kerberos SSO.
 *
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

    /*package for testing*/ final transient @NonNull Map<String, String> config;

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
    /*package*/ KerberosSSOFilter(@NonNull Map<String, String> config, @NonNull KerberosAuthenticatorFactory authenticatorFactory) {
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

        final HttpServletResponse httpResponse = (HttpServletResponse)response;
        final HttpServletRequest httpRequest = (HttpServletRequest)request;

        if (skipAuthentication(httpRequest)) {
            chain.doFilter(request, response);
            return;
        }

        final String userContentPath = httpRequest.getContextPath() + "/userContent";
        if (httpRequest.getRequestURI().startsWith(userContentPath)) {
            chain.doFilter(request, response);
            return;
        }

        final SpnegoHttpServletResponse spnegoHttpResponse = new SpnegoHttpServletResponse(httpResponse);

        final PluginImpl plugin = PluginImpl.getInstance();
        if (plugin.isRedirectEnabled()
                && !httpRequest.getLocalAddr().equals(httpRequest.getRemoteAddr())) {
                // If Local and Remote address is the same, the user is Localhost and shouldn't be redirected.

            String requestedDomain = new URL(httpRequest.getRequestURL().toString()).getHost();
            String requestedURL = httpRequest.getRequestURL().toString();
            if (!requestedDomain.toLowerCase().contains(plugin.getRedirect().toLowerCase())) {

                String redirect = requestedURL.replaceFirst(
                        requestedDomain, requestedDomain + "." + plugin.getRedirect());
                logger.fine("Redirecting request to " + redirect);
                spnegoHttpResponse.sendRedirect(redirect);
            }
        }

        if (!isAuthenticated()) {
            Functions.advertiseHeaders(httpResponse); // Adds headers for CLI

            Principal principal;

            try {
                logger.fine("Authenticating request");
                principal = authenticator.authenticate(httpRequest, spnegoHttpResponse);
                if (principal != null) {
                    logger.log(Level.INFO, "Authenticated principal {0}", principal.getName());
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

            final Jenkins jenkins = Jenkins.get();
            try {
                SecurityRealm realm = jenkins.getSecurityRealm();
                UserDetails userDetails = realm.loadUserByUsername2(principalName);
                String username = userDetails.getUsername();
                Authentication authToken = new UsernamePasswordAuthenticationToken(
                        username,
                        userDetails.getPassword(),
                        userDetails.getAuthorities());

                ACL.impersonate2(authToken);

                populateUserSeed(httpRequest, username);
                SecurityListener.fireLoggedIn(username);
                logger.log(Level.INFO, "Authenticated user {0}", username);
            } catch (UsernameNotFoundException e) {
                logger.log(Level.WARNING, "Username {0} not registered by Jenkins", principalName);
            } catch (Exception e) {
                logger.log(Level.WARNING, "User authentication failed", e);
            }
        }

        // User is authenticated, do not stay on login page
        if (isAuthenticated() && isAccessingLoginGateway(httpRequest)) {
            // After successful negotiation or Basic auth (JENKINS-38687).

            // The basic authentication is only advertised by KerberosSSOFilter and spnego. It is processed by
            // jenkins.security.BasicHeaderProcessor so the request enters this filter authenticated already.
            String redirectTarget = getRedirectTarget(httpRequest);
            logger.fine("Redirecting to " + redirectTarget);
            httpResponse.sendRedirect(redirectTarget);
            return;
        }

        chain.doFilter(request, response);
    }

    /**
     * This request is in a filter before the Stapler for pre-authentication for that reason we need to keep the code
     * that applies the same logic as UserSeedSecurityListener.
     *
     * @param httpRequest Current request.
     * @param username Authenticated username.
     */
    @SuppressRestrictedWarnings(UserSeedProperty.class)
    private void populateUserSeed(HttpServletRequest httpRequest, String username) {
        // Adapted from hudson.security.AuthenticationProcessingFilter2
        HttpSession newSession = httpRequest.getSession();
        if (!UserSeedProperty.DISABLE_USER_SEED) {
            User user = User.getById(username, true);

            UserSeedProperty userSeed = user.getProperty(UserSeedProperty.class);
            String sessionSeed = userSeed.getSeed();
            newSession.setAttribute(UserSeedProperty.USER_SESSION_SEED, sessionSeed);
        }
    }

    /**
     * Get URL to redirect after successful explicit authentication.
     *
     * @param req The request.
     * @return The URL.
     */
    private String getRedirectTarget(HttpServletRequest req) {
        final String contextPath = req.getContextPath();

        String from = Util.fixEmptyAndTrim(req.getParameter("from"));
        // see Jenkins.doLoginEntry
        if (from != null && from.startsWith("/") && !from.equals("/loginError")) {
            // Imported from hudson.security.AuthenticationProcessingFilter2.determineTargetUrl
            if (!Util.isSafeToRedirectTo(from)) {
                return contextPath; // avoid open redirect
            }

            // Based on code from hudson.security.AuthenticationProcessingFilter2.determineTargetUrl
            // handles case where 'from' contains Context Path
            if (from.startsWith(contextPath)) {
                return from;
            }

            return contextPath + from;
        }

        // Jenkins dashboard otherwise
        return contextPath;
    }

    /**
     * Is current user authenticated.
     *
     * @return true if it is.
     */
    private boolean isAuthenticated() {
        return !Functions.isAnonymous();
    }

    /**
     * Should the request authentication be skipped.
     * @param request Handled request.
     * @return true if request should not be authenticated.
     */
    private boolean skipAuthentication(HttpServletRequest request) {
        if (PluginImpl.getInstance().getAnonymousAccess() && !isAccessingLoginGateway(request)) {
            return true;
        }

        Jenkins jenkins = Jenkins.get();
        String rest = request.getPathInfo();
        for (String name : jenkins.getUnprotectedRootActions()) {
            if (rest.startsWith("/" + name + "/") || rest.equals("/" + name)) {
                logger.log(Level.FINEST, "Authentication not required: Unprotected root action: " + rest);
                return true;
            }
        }

        return request.getHeader(BYPASS_HEADER) != null;
    }

    /**
     * Is performing explicit authentication.
     * @param request Handled request.
     * @return true if request accessing login url for explicit authentication.
     */
    private boolean isAccessingLoginGateway(HttpServletRequest request) {
        return "/login".equals(request.getPathInfo());
    }

    /**
     * Called if the filter needs to be destroyed.
     */
    public void destroy() {
        logger.info("Kerberos filter destroyed");
        if (authenticator != null) {
            authenticator.dispose();
        }
    }
}
