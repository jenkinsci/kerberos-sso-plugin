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

import com.gargoylesoftware.htmlunit.html.HtmlAnchor;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.sonymobile.jenkins.plugins.kerberossso.ioc.KerberosAuthenticator;
import com.sonymobile.jenkins.plugins.kerberossso.ioc.KerberosAuthenticatorFactory;
import hudson.util.PluginServletFilter;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.JenkinsRule.WebClient;

import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.PrivilegedActionException;
import java.util.Map;

import static java.util.Collections.EMPTY_MAP;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.jvnet.hudson.test.JenkinsRule.DummySecurityRealm;
import static org.mockito.Matchers.any;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.when;

/**
 * Testing the filter functionality of the Kerberos Single Sign-on plugin.
 * The tests uses mockito to mock a SPNEGO authenticator. This is because
 * whether the authenticator works or not is up to each setup and does not
 * depend on the code in this plugin.
 * @author Joakim Ahle &lt;joakim.ahle@sonyericsson.com&gt;
 * @author Fredrik Persson &lt;fredrik6.persson@sonyericsson.com&gt;
 */
public class KerberosFilterTest {

    /**
     * Jnekins rule instance.
     */
    // CS IGNORE VisibilityModifier FOR NEXT 3 LINES. REASON: Mocks tests.
    @Rule
    public JenkinsRule rule = new JenkinsRule();

    /**
     * Sets up the tests by creating a SecurityRealm.
     */
    @Before
    public void setUp() {
        DummySecurityRealm realm = rule.createDummySecurityRealm();
        rule.jenkins.setSecurityRealm(realm);
    }

    /**
     * Tests that the user is logged in if authentication succeeds.
     * @throws Exception if something goes wrong.
     */
    @Test
    public void testSuccessfullyAuthenticateUser() throws Exception {
        KerberosSSOFilter filter = new KerberosSSOFilter(EMPTY_MAP, new KerberosAuthenticatorFactory() {
            @Override
            public KerberosAuthenticator getInstance(Map<String, String> config)
                    throws LoginException, IOException, URISyntaxException, PrivilegedActionException {

                KerberosAuthenticator mockAuthenticator = mock(KerberosAuthenticator.class);
                when(mockAuthenticator.authenticate(
                        any(HttpServletRequest.class), any(HttpServletResponse.class)))
                        .thenReturn(new KerberosPrincipal("mockUser"));

                return mockAuthenticator;
            }
        });
        PluginServletFilter.addFilter(filter);

        WebClient wc = rule.createWebClient();
        wc.goTo("login");
        HtmlPage mainPage = wc.goTo("");

        assertNotNull(mainPage);
        assertTrue(mainPage.asText().contains("mockUser"));

        PluginServletFilter.removeFilter(filter);
    }

    /**
     * Tests that the user is not logged in if authentication is unsuccessful.
     * @throws Exception if something goes wrong.
     */
    @Test
    public void testUnsuccessfulAuthentication() throws Exception {
        KerberosSSOFilter filter = new KerberosSSOFilter(EMPTY_MAP, new KerberosAuthenticatorFactory() {
            @Override
            public KerberosAuthenticator getInstance(Map<String, String> config)
                    throws LoginException, IOException, URISyntaxException, PrivilegedActionException {

                KerberosAuthenticator mockAuthenticator =  mock(KerberosAuthenticator.class);
                when(mockAuthenticator.authenticate(
                        any(HttpServletRequest.class), any(HttpServletResponse.class)))
                        .thenThrow(new LoginException());

                return mockAuthenticator;
            }
        });
        PluginServletFilter.addFilter(filter);

        WebClient wc = rule.createWebClient();
        wc.goTo("login");
        HtmlPage mainPage = wc.goTo("");

        assertNotNull(mainPage);
        assertTrue(((HtmlAnchor)mainPage.getFirstByXPath(
                "//*[@id=\"login-field\"]/span/a")).getHrefAttribute().contains("login"));

        PluginServletFilter.removeFilter(filter);
    }
}
