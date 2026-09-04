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
import hudson.model.RootAction;
import hudson.model.User;
import hudson.security.ACL;
import hudson.security.ACLContext;
import hudson.util.PluginServletFilter;
import jenkins.model.Jenkins;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.jvnet.hudson.test.TestExtension;
import org.kohsuke.stapler.StaplerResponse2;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import javax.security.auth.kerberos.KerberosPrincipal;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Machine principals ({@code host/fqdn@REALM}, {@code NAME$@REALM}) authenticating as themselves.
 */
public class MachinePrincipalTest {

    // CS IGNORE VisibilityModifier FOR NEXT 2 LINES. REASON: JenkinsRule.
    @Rule
    public JenkinsRule rule = new JenkinsRule();

    private KerberosSSOFilter filter;

    @Before
    public void setUp() {
        rule.jenkins.setSecurityRealm(rule.createDummySecurityRealm());
        // Every URL negotiates, so the identity endpoint below is reached authenticated
        PluginImpl.getInstance().setAnonymousAccess(false);
    }

    @After
    public void tearDown() throws ServletException {
        if (filter != null) {
            PluginServletFilter.removeFilter(filter);
        }
    }

    @Test
    public void allowlistedMachineAuthenticatesAsItself() throws Exception {
        fakePrincipal("host/agent01.example.com@EXAMPLE.COM");
        patterns("host/*@EXAMPLE.COM");

        Identity who = identity();
        assertEquals("host/agent01.example.com@example.com", who.name);
        assertTrue("machine group expected", who.authorities.contains(MachinePrincipalMapper.GROUP));
        assertFalse("must not inherit the authenticated group", who.authorities.contains("authenticated"));
    }

    @Test
    public void computerAccountsAreRecognised() throws Exception {
        fakePrincipal("AGENT01$@EXAMPLE.COM");
        patterns("*$@example.com");

        assertEquals("agent01$@example.com", identity().name);
    }

    @Test
    public void machineOutsideAllowlistStaysAnonymous() throws Exception {
        fakePrincipal("host/agent01.example.com@EXAMPLE.COM");
        patterns("host/*@OTHER.COM");

        assertEquals("anonymous", identity().name);
    }

    @Test
    public void machinesAreAnonymousWhenNothingIsConfigured() throws Exception {
        fakePrincipal("host/agent01.example.com@EXAMPLE.COM");

        assertEquals("anonymous", identity().name);
    }

    @Test
    public void denyEntryRevokesASingleMachine() throws Exception {
        fakePrincipal("STOLEN$@EXAMPLE.COM");
        patterns("*$@EXAMPLE.COM", "!stolen$@EXAMPLE.COM");

        assertEquals("anonymous", identity().name);
    }

    @Test
    public void userPrincipalsStillTakeTheRealmPath() throws Exception {
        fakePrincipal("mockUser@EXAMPLE.COM");
        patterns("*@EXAMPLE.COM");

        Identity who = identity();
        assertEquals("mockUser", who.name);
        assertTrue(who.authorities.contains("authenticated"));
        assertFalse(who.authorities.contains(MachinePrincipalMapper.GROUP));
    }

    @Test
    public void patternsMustNameARealm() {
        assertThrows(IllegalArgumentException.class,
                () -> PluginImpl.getInstance().setMachinePrincipalPatterns(Collections.singletonList("host/*")));
    }

    @Test
    public void onlyAdministratorsMayConfigurePatterns() {
        rule.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy()
                .grant(Jenkins.READ).everywhere().to("bob"));
        try (ACLContext ignored = ACL.as2(User.getById("bob", true).impersonate2())) {
            assertThrows(AccessDeniedException.class,
                    () -> PluginImpl.getInstance().setMachinePrincipalPatterns(Collections.singletonList("*@X")));
            assertThrows(AccessDeniedException.class,
                    () -> PluginImpl.getInstance().getMachinePrincipalPatternsString());
        }
    }

    /**
     * Reports the identity of the current request. A protected action, unlike /whoAmI, so the filter
     * runs and the reported identity is the one the filter established.
     */
    @TestExtension
    public static class IdentityAction implements RootAction {
        @Override public String getIconFileName() { return null; }
        @Override public String getDisplayName() { return null; }
        @Override public String getUrlName() { return "identity"; }

        public void doIndex(StaplerResponse2 rsp) throws IOException {
            Authentication a = Jenkins.getAuthentication2();
            rsp.setContentType("text/plain;charset=UTF-8");
            rsp.getWriter().print(a.getName() + "|" + a.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority).collect(Collectors.joining(",")));
        }
    }

    private static final class Identity {
        final String name;
        final List<String> authorities;

        Identity(String raw) {
            String[] parts = raw.split("\\|", -1);
            name = parts[0];
            authorities = parts.length > 1 && !parts[1].isEmpty()
                    ? Arrays.asList(parts[1].split(",")) : Collections.emptyList();
        }
    }

    private Identity identity() throws IOException {
        try (CloseableHttpClient client = HttpClients.createMinimal()) {
            HttpGet get = new HttpGet(rule.getURL().toExternalForm() + "identity/");
            try (CloseableHttpResponse response = client.execute(get)) {
                assertEquals(200, response.getStatusLine().getStatusCode());
                return new Identity(EntityUtils.toString(response.getEntity()));
            }
        }
    }

    private static void patterns(String... patterns) {
        PluginImpl.getInstance().setMachinePrincipalPatterns(Arrays.asList(patterns));
    }

    private void fakePrincipal(String principal) throws Exception {
        KerberosAuthenticator mockAuthenticator = mock(KerberosAuthenticator.class);
        when(mockAuthenticator.authenticate(any(HttpServletRequest.class), any(HttpServletResponse.class)))
                .thenReturn(new KerberosPrincipal(principal));
        filter = new KerberosSSOFilter(Collections.emptyMap(), config -> mockAuthenticator);
        PluginServletFilter.addFilter(filter);
    }
}
