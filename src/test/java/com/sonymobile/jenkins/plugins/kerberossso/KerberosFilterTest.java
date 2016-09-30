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
import hudson.FilePath;
import hudson.util.PluginServletFilter;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.io.IOUtils;
import org.apache.tools.ant.util.JavaEnvUtils;
import org.hamcrest.Matcher;
import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.JenkinsRule.WebClient;

import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.LoginException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.PrivilegedActionException;
import java.util.Collections;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertEquals;
import static org.jvnet.hudson.test.JenkinsRule.DummySecurityRealm;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Testing the filter functionality of the Kerberos Single Sign-on plugin.
 *
 * The tests uses mockito to mock a SPNEGO authenticator. This is because
 * whether the authenticator works or not is up to each setup and does not
 * depend on the code in this plugin.
 *
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

    @Rule
    // CS IGNORE VisibilityModifier FOR NEXT 1 LINES. REASON: Mocks tests.
    public TemporaryFolder tmp = new TemporaryFolder();

    // Reference to filter to remove after test
    private KerberosSSOFilter filter;

    WebClient wc;

    /**
     * Sets up the tests by creating a SecurityRealm.
     */
    @Before
    public void setUp() {
        DummySecurityRealm realm = rule.createDummySecurityRealm();
        rule.jenkins.setSecurityRealm(realm);
    }

    @After
    public void tearDown() throws ServletException {
        if (filter != null) {
            PluginServletFilter.removeFilter(filter);
        }
    }

    /**
     * Tests that the user is logged in if authentication succeeds.
     */
    @Test
    public void testSuccessfullyAuthenticateUser() throws Exception {
        fakePrincipal("mockUser@TEST.COM");

        PluginImpl.getInstance().setLoginAllURLs(true);
        wc = rule.createWebClient();
        assertThat(wc.goTo("whoAmI").asText(), authorized());

        PluginImpl.getInstance().setLoginAllURLs(false);
        wc = rule.createWebClient();
        assertThat(wc.goTo("whoAmI").asText(), not(authorized()));

        wc.goTo("login");
        assertThat(wc.goTo("whoAmI").asText(), authorized());
    }

    /**
     * Tests that the user is not logged in if authentication is unsuccessful.
     */
    @Test
    public void testUnsuccessfulAuthentication() throws Exception {
        rejectAuthentication();

        PluginImpl.getInstance().setLoginAllURLs(true);
        wc = rule.createWebClient();
        assertThat(wc.goTo("whoAmI").asText(), not(authorized()));

        PluginImpl.getInstance().setLoginAllURLs(false);
        wc = rule.createWebClient();
        wc.goTo("login");
        assertThat(wc.goTo("whoAmI").asText(), not(authorized()));
    }

    /**
    * Tests that the user is not logged in if trying to access /userContent/.
    */
    @Test
    public void testIgnoreAuthenticationForUserContent() throws Exception {
        fakePrincipal("mockUser@TEST.COM");

        // This only makes sense when login is required for all URLs
        PluginImpl.getInstance().setLoginAllURLs(true);

        String userContent = rule.createWebClient().goTo("userContent/").asText();
        assertThat(userContent, containsString("log in"));
    }

    @Test
    public void skipFilterWhenCliUsed() throws Exception {
        // This only makes sense when login is required for all URLs
        PluginImpl.getInstance().setLoginAllURLs(true);

        // Turn of the jnlp port to make sure this used servlet request
        rule.jenkins.getTcpSlaveAgentListener().shutdown();

        rejectAuthentication();
        URL jar = rule.jenkins.servletContext.getResource("/WEB-INF/jenkins-cli.jar");
        FilePath cliJar = new FilePath(tmp.getRoot()).child("cli.jar");
        cliJar.copyFrom(jar);

        Process start = new ProcessBuilder(
                JavaEnvUtils.getJreExecutable("java"),
                "-jar", cliJar.getRemote(),
                "-s", rule.getURL().toExternalForm(),
                "help"
        ).start();

        String err = IOUtils.toString(start.getErrorStream());
        assertThat(err, containsString("who-am-i"));
        assertThat(err, containsString("Reports your credential and permissions"));

        assertEquals(err, 0, start.waitFor());
    }

    @Test
    public void skipFilterWhenBypassHeaderProvided() throws Exception {
        fakePrincipal("mockUser@TEST.COM");
        // This only makes sense when login is required for all URLs
        PluginImpl.getInstance().setLoginAllURLs(true);

        HttpClient client = new HttpClient();

        String url = rule.getURL().toExternalForm() + "/whoAmI";
        GetMethod get = new GetMethod(url);
        client.executeMethod(get);
        String out = get.getResponseBodyAsString();
        assertThat(out, authorized());

        client = new HttpClient();
        get = new GetMethod(url);
        get.setRequestHeader(KerberosSSOFilter.BYPASS_HEADER, ".");
        client.executeMethod(get);
        out = get.getResponseBodyAsString();
        assertThat(out, not(authorized()));
    }

    private Matcher<String> authorized() {
        return Matchers.allOf(containsString("mockUser"), not(containsString("anonymous")));
    }

    private void rejectAuthentication() throws LoginException, IOException, ServletException {
        KerberosAuthenticator mockAuthenticator = mock(KerberosAuthenticator.class);
        when(mockAuthenticator.authenticate(any(HttpServletRequest.class), any(HttpServletResponse.class)))
                .thenThrow(new LoginException())
        ;
        registerFilter(mockAuthenticator);
    }

    private void fakePrincipal(String principal) throws LoginException, IOException, ServletException {
        KerberosAuthenticator mockAuthenticator = mock(KerberosAuthenticator.class);
        when(mockAuthenticator.authenticate(any(HttpServletRequest.class), any(HttpServletResponse.class)))
                .thenReturn(new KerberosPrincipal(principal))
        ;
        registerFilter(mockAuthenticator);
    }

    private void registerFilter(final KerberosAuthenticator mockAuthenticator) throws ServletException {
        filter = new KerberosSSOFilter(Collections.<String, String>emptyMap(), new KerberosAuthenticatorFactory() {
            @Override
            public KerberosAuthenticator getInstance(Map<String, String> config)
                    throws LoginException, IOException, URISyntaxException, PrivilegedActionException {
                return mockAuthenticator;
            }
        });
        PluginServletFilter.addFilter(filter);
    }
}
