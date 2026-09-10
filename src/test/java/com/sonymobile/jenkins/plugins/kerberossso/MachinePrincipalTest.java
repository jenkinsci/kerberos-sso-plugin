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
import hudson.model.Cause;
import hudson.model.FreeStyleProject;
import hudson.model.Item;
import hudson.model.RootAction;
import hudson.model.User;
import hudson.security.ACL;
import hudson.security.ACLContext;
import hudson.security.AuthorizationMatrixProperty;
import hudson.security.ProjectMatrixAuthorizationStrategy;
import hudson.security.csrf.DefaultCrumbIssuer;
import hudson.util.PluginServletFilter;
import jenkins.model.Jenkins;
import jenkins.security.seed.UserSeedProperty;
import net.sf.json.JSONObject;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.jenkinsci.plugins.matrixauth.PermissionEntry;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.jvnet.hudson.test.TestExtension;
import org.kohsuke.stapler.StaplerRequest2;
import org.kohsuke.stapler.StaplerResponse2;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import javax.security.auth.kerberos.KerberosPrincipal;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Machine principals ({@code host/fqdn@REALM}, {@code NAME$@REALM}) authenticating as themselves.
 */
public class MachinePrincipalTest {

    // CS IGNORE VisibilityModifier FOR NEXT 2 LINES. REASON: JenkinsRule.
    @Rule
    public JenkinsRule rule = new JenkinsRule();

    private KerberosSSOFilter filter;
    private KerberosAuthenticator authenticator;
    private boolean ticketAvailable = true;

    @Before
    public void setUp() {
        rule.jenkins.setSecurityRealm(rule.createDummySecurityRealm());
        // Every URL negotiates, so the identity endpoint below is reached authenticated
        PluginImpl.getInstance().setAnonymousAccess(false);
    }

    @After
    public void tearDown() throws ServletException {
        if (filter != null) {
            PluginImpl.getInstance().removeFilter();
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

    /**
     * The allowlist decides, not the shape of the principal. A machine no pattern matches keeps the
     * realm lookup it had before this feature existed. The dummy realm resolves any name, standing
     * in for a realm that resolves computer accounts.
     */
    @Test
    public void machineOutsideAllowlistFallsBackToTheSecurityRealm() throws Exception {
        fakePrincipal("host/agent01.example.com@EXAMPLE.COM");
        patterns("host/*@OTHER.COM");

        Identity who = identity();
        assertEquals("host/agent01.example.com", who.name);
        assertTrue(who.authorities.contains("authenticated"));
        assertFalse(who.authorities.contains(MachinePrincipalMapper.GROUP));
    }

    /** Configuring nothing must change nothing. */
    @Test
    public void machinesKeepTheirRealmLookupWhenNothingIsConfigured() throws Exception {
        fakePrincipal("host/agent01.example.com@EXAMPLE.COM");

        assertEquals("host/agent01.example.com", identity().name);
    }

    /**
     * A Kerberos instance name such as alice/admin is a person, not a machine. It has machine shape,
     * so no pattern must be needed for it to keep resolving as the user it belongs to.
     */
    @Test
    public void kerberosInstanceNamesStillResolveAsPeople() throws Exception {
        fakePrincipal("alice/admin@EXAMPLE.COM");
        patterns("host/*@EXAMPLE.COM -> ci-servers");

        Identity who = identity();
        assertEquals("alice/admin", who.name);
        assertTrue(who.authorities.contains("authenticated"));
        assertFalse(who.authorities.contains(MachinePrincipalMapper.GROUP));
    }

    /**
     * Denial must not fall back to the realm. Otherwise revoking a computer account would restore it
     * as an ordinary user carrying "authenticated", which is the opposite of revoking it.
     */
    @Test
    public void deniedMachineStaysAnonymousRatherThanReachingTheRealm() throws Exception {
        fakePrincipal("STOLEN$@EXAMPLE.COM");
        patterns("!stolen$@EXAMPLE.COM");

        Identity who = identity();
        assertEquals("anonymous", who.name);
        assertFalse(who.authorities.contains("authenticated"));
    }

    /** Denying a whole class is how an operator opts into machines never reaching the realm. */
    @Test
    public void aDenyGlobLocksOutEveryComputerAccount() throws Exception {
        fakePrincipal("AGENT01$@EXAMPLE.COM");
        patterns("!*$@EXAMPLE.COM");

        assertEquals("anonymous", identity().name);
    }

    /**
     * A session cookie must not retain machine authentication, even when an endpoint creates a
     * session and core's user seed checks are disabled. Each protected request needs a ticket.
     */
    @Test
    public void machineAuthenticationIsStatelessPerRequest() throws Exception {
        fakePrincipal("host/agent01.example.com@EXAMPLE.COM");
        patterns("host/*@EXAMPLE.COM");

        boolean original = UserSeedProperty.DISABLE_USER_SEED;
        UserSeedProperty.DISABLE_USER_SEED = true;
        BasicCookieStore cookies = new BasicCookieStore();
        try (CloseableHttpClient client = HttpClients.custom().setDefaultCookieStore(cookies).build()) {
            String base = rule.getURL().toExternalForm();
            try (CloseableHttpResponse first = client.execute(new HttpGet(base + "identity/"))) {
                assertTrue(EntityUtils.toString(first.getEntity()).startsWith("host/agent01.example.com@example.com|"));
            }
            assertFalse("the identity endpoint created a session", cookies.getCookies().isEmpty());
            try (CloseableHttpResponse second = client.execute(new HttpGet(base + "whoAmI/api/json"))) {
                assertTrue(EntityUtils.toString(second.getEntity()).contains("\"name\":\"anonymous\""));
            }
            ticketAvailable = false;
            try (CloseableHttpResponse third = client.execute(new HttpGet(base + "identity/"))) {
                assertEquals("a cookie alone cannot authenticate", 401, third.getStatusLine().getStatusCode());
            }
        } finally {
            UserSeedProperty.DISABLE_USER_SEED = original;
        }
    }


    /**
     * The use case this exists for: a class of machines granted Job/Build on one job and nothing
     * else, using production Matrix Authorization and CSRF protection. A cookie retains the crumb
     * session, while Kerberos authenticates each request. The build records the machine's identity.
     */
    @Test
    public void laptopGroupCanTriggerOnlyTheJobItIsGranted() throws Exception {
        FreeStyleProject callback = rule.createFreeStyleProject("callback");
        FreeStyleProject offLimits = rule.createFreeStyleProject("off-limits");
        ProjectMatrixAuthorizationStrategy strategy = new ProjectMatrixAuthorizationStrategy();
        strategy.add(Jenkins.READ, PermissionEntry.group("laptop-callbacks"));
        rule.jenkins.setAuthorizationStrategy(strategy);
        AuthorizationMatrixProperty permissions = new AuthorizationMatrixProperty(Collections.emptyList());
        permissions.add(Item.READ, PermissionEntry.group("laptop-callbacks"));
        permissions.add(Item.BUILD, PermissionEntry.group("laptop-callbacks"));
        callback.addProperty(permissions);
        rule.jenkins.setCrumbIssuer(new DefaultCrumbIssuer(false));

        fakePrincipal("host/marcos-laptop-1.remote.example.com@EXAMPLE.COM");
        patterns("host/*-laptop-*.remote.example.com@EXAMPLE.COM -> laptop-callbacks");

        assertEquals(201, post("job/callback/build"));
        rule.waitUntilNoActivity();
        assertEquals("the granted job ran", 1, callback.getBuilds().size());

        Cause.UserIdCause cause = callback.getLastBuild().getCause(Cause.UserIdCause.class);
        assertNotNull(cause);
        assertEquals("host/marcos-laptop-1.remote.example.com@example.com", cause.getUserId());

        // 404 rather than 403: without Item.READ Jenkins hides the job instead of admitting it exists
        assertEquals("the ungranted job did not", 404, post("job/off-limits/build"));
        assertEquals(0, offLimits.getBuilds().size());
    }

    /**
     * KerberosPreCrumbAuthentication runs the filter inside CrumbFilter, and PluginServletFilter
     * reaches it again on the same request. A POST must negotiate once, so the ticket is never
     * presented to the authenticator twice.
     */
    @Test
    public void aPostNegotiatesOnlyOnce() throws Exception {
        FreeStyleProject callback = rule.createFreeStyleProject("callback");
        ProjectMatrixAuthorizationStrategy strategy = new ProjectMatrixAuthorizationStrategy();
        strategy.add(Jenkins.READ, PermissionEntry.group("laptop-callbacks"));
        rule.jenkins.setAuthorizationStrategy(strategy);
        AuthorizationMatrixProperty permissions = new AuthorizationMatrixProperty(Collections.emptyList());
        permissions.add(Item.READ, PermissionEntry.group("laptop-callbacks"));
        permissions.add(Item.BUILD, PermissionEntry.group("laptop-callbacks"));
        callback.addProperty(permissions);
        rule.jenkins.setCrumbIssuer(new DefaultCrumbIssuer(false));

        fakePrincipal("host/marcos-laptop-1.remote.example.com@EXAMPLE.COM");
        patterns("host/*-laptop-*.remote.example.com@EXAMPLE.COM -> laptop-callbacks");

        try (CloseableHttpClient client = HttpClients.custom()
                .setDefaultCookieStore(new BasicCookieStore()).build()) {
            JSONObject crumb = crumb(client);
            clearInvocations(authenticator);

            HttpPost req = new HttpPost(rule.getURL().toExternalForm() + "job/callback/build");
            req.addHeader(crumb.getString("crumbRequestField"), crumb.getString("crumb"));
            try (CloseableHttpResponse response = client.execute(req)) {
                EntityUtils.consumeQuietly(response.getEntity());
                assertEquals(201, response.getStatusLine().getStatusCode());
            }
        }

        verify(authenticator, times(1))
                .authenticate(any(HttpServletRequest.class), any(HttpServletResponse.class));
        rule.waitUntilNoActivity();
        assertEquals(1, callback.getBuilds().size());
    }

    @Test
    public void defaultCrumbRequiresItsSessionCookie() throws Exception {
        FreeStyleProject callback = rule.createFreeStyleProject("callback");
        rule.jenkins.setCrumbIssuer(new DefaultCrumbIssuer(false));
        fakePrincipal("host/agent01.example.com@EXAMPLE.COM");
        patterns("host/*@EXAMPLE.COM");

        assertEquals("a crumb without its cookie is invalid", 403, post("job/callback/build", false));
        assertEquals(0, callback.getBuilds().size());
    }

    @Test
    public void machinePostRequiresBothTicketAndValidCrumb() throws Exception {
        FreeStyleProject callback = rule.createFreeStyleProject("callback");
        rule.jenkins.setCrumbIssuer(new DefaultCrumbIssuer(false));
        fakePrincipal("host/agent01.example.com@EXAMPLE.COM");
        patterns("host/*@EXAMPLE.COM");
        try (CloseableHttpClient client = HttpClients.custom().setDefaultCookieStore(new BasicCookieStore()).build()) {
            JSONObject crumb = crumb(client);
            String url = rule.getURL().toExternalForm() + "job/callback/build";
            try (CloseableHttpResponse missing = client.execute(new HttpPost(url))) {
                assertEquals(403, missing.getStatusLine().getStatusCode());
            }
            HttpPost invalid = new HttpPost(url);
            invalid.setHeader(crumb.getString("crumbRequestField"), "invalid");
            try (CloseableHttpResponse response = client.execute(invalid)) {
                assertEquals(403, response.getStatusLine().getStatusCode());
            }
            ticketAvailable = false;
            HttpPost noTicket = new HttpPost(url);
            noTicket.setHeader(crumb.getString("crumbRequestField"), crumb.getString("crumb"));
            try (CloseableHttpResponse response = client.execute(noTicket)) {
                assertEquals(401, response.getStatusLine().getStatusCode());
                assertEquals("Negotiate", response.getFirstHeader("WWW-Authenticate").getValue());
            }
        }
        assertEquals(0, callback.getBuilds().size());
        assertTrue(rule.jenkins.getQueue().isEmpty());
    }

    @Test
    public void preCrumbAuthenticationRespectsDisabledAndBypassedConfigurations() throws Exception {
        rule.jenkins.setCrumbIssuer(new DefaultCrumbIssuer(false));
        fakePrincipal("host/agent01.example.com@EXAMPLE.COM");
        ticketAvailable = false;
        PluginImpl plugin = PluginImpl.getInstance();
        String url = rule.getURL().toExternalForm() + "identity/";
        try (CloseableHttpClient client = HttpClients.createMinimal()) {
            // Empty patterns preserve the existing crumb-first behavior.
            try (CloseableHttpResponse response = client.execute(new HttpPost(url))) {
                assertEquals(403, response.getStatusLine().getStatusCode());
            }
            patterns("host/*@EXAMPLE.COM");
            plugin.setEnabled(false);
            try (CloseableHttpResponse response = client.execute(new HttpPost(url))) {
                assertEquals(403, response.getStatusLine().getStatusCode());
            }
            plugin.setEnabled(true);
            plugin.setBypassPaths(Collections.singletonList("/identity"));
            try (CloseableHttpResponse response = client.execute(new HttpPost(url))) {
                assertEquals(403, response.getStatusLine().getStatusCode());
            }
        }
    }

    @Test
    public void denyRevokesPostWithAnExistingCrumbAndCookie() throws Exception {
        FreeStyleProject callback = rule.createFreeStyleProject("callback");
        rule.jenkins.setCrumbIssuer(new DefaultCrumbIssuer(false));
        fakePrincipal("STOLEN$@EXAMPLE.COM");
        patterns("*$@EXAMPLE.COM");
        try (CloseableHttpClient client = HttpClients.custom().setDefaultCookieStore(new BasicCookieStore()).build()) {
            JSONObject crumb = crumb(client);
            patterns("*$@EXAMPLE.COM", "!stolen$@EXAMPLE.COM");
            HttpPost revoked = new HttpPost(rule.getURL().toExternalForm() + "job/callback/build");
            revoked.setHeader(crumb.getString("crumbRequestField"), crumb.getString("crumb"));
            try (CloseableHttpResponse response = client.execute(revoked)) {
                assertEquals(403, response.getStatusLine().getStatusCode());
            }
        }
        assertEquals(0, callback.getBuilds().size());
        assertTrue(rule.jenkins.getQueue().isEmpty());
    }

    @Test
    public void denyRevokesMachineWithAnExistingSessionCookie() throws Exception {
        fakePrincipal("STOLEN$@EXAMPLE.COM");
        patterns("*$@EXAMPLE.COM");
        boolean original = UserSeedProperty.DISABLE_USER_SEED;
        UserSeedProperty.DISABLE_USER_SEED = true;
        BasicCookieStore cookies = new BasicCookieStore();
        try (CloseableHttpClient client = HttpClients.custom().setDefaultCookieStore(cookies).build()) {
            String url = rule.getURL().toExternalForm() + "identity/";
            try (CloseableHttpResponse first = client.execute(new HttpGet(url))) {
                assertTrue(EntityUtils.toString(first.getEntity()).startsWith("stolen$@example.com|"));
            }
            assertFalse(cookies.getCookies().isEmpty());
            patterns("*$@EXAMPLE.COM", "!stolen$@EXAMPLE.COM");
            try (CloseableHttpResponse next = client.execute(new HttpGet(url))) {
                assertTrue("deny takes effect on the next request",
                        EntityUtils.toString(next.getEntity()).startsWith("anonymous|"));
            }
        } finally {
            UserSeedProperty.DISABLE_USER_SEED = original;
        }
    }

    @Test
    public void machineGetsEveryGroupItsMatchingPatternsName() throws Exception {
        fakePrincipal("host/ci01.example.com@EXAMPLE.COM");
        patterns("host/*@EXAMPLE.COM -> all-machines",
                 "host/ci*@EXAMPLE.COM -> ci-servers, Production");

        List<String> held = identity().authorities;
        assertTrue(held.contains(MachinePrincipalMapper.GROUP));
        assertTrue(held.contains("all-machines"));
        assertTrue(held.contains("ci-servers"));
        assertTrue("group names keep their case", held.contains("Production"));
        assertFalse(held.contains("authenticated"));
    }

    @Test
    public void groupsAreNotGrantedToMachinesOutsideThePattern() throws Exception {
        fakePrincipal("host/db01.example.com@EXAMPLE.COM");
        patterns("host/*@EXAMPLE.COM", "host/ci*@EXAMPLE.COM -> ci-servers");

        List<String> held = identity().authorities;
        assertTrue(held.contains(MachinePrincipalMapper.GROUP));
        assertFalse("db01 is not a ci server", held.contains("ci-servers"));
    }

    @Test
    public void denyPatternsMayNotGrantGroups() {
        assertThrows(IllegalArgumentException.class, () -> PluginImpl.getInstance()
                .setMachinePrincipalPatterns(Collections.singletonList("!a$@X -> some-group")));
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

        public void doIndex(StaplerRequest2 req, StaplerResponse2 rsp) throws IOException {
            // Exercise session persistence as real endpoints (including the crumb issuer) can.
            req.getSession();
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

    /** @return status of a POST, fetching a CSRF crumb first when the controller issues one. */
    private int post(String path) throws IOException {
        return post(path, true);
    }

    private int post(String path, boolean retainCookie) throws IOException {
        try (CloseableHttpClient client = retainCookie
                ? HttpClients.custom().setDefaultCookieStore(new BasicCookieStore()).build()
                : HttpClients.createMinimal()) {
            String base = rule.getURL().toExternalForm();
            HttpPost req = new HttpPost(base + path);
            JSONObject crumb = crumb(client);
            req.addHeader(crumb.getString("crumbRequestField"), crumb.getString("crumb"));
            try (CloseableHttpResponse response = client.execute(req)) {
                EntityUtils.consumeQuietly(response.getEntity());
                return response.getStatusLine().getStatusCode();
            }
        }
    }

    private JSONObject crumb(CloseableHttpClient client) throws IOException {
        String url = rule.getURL().toExternalForm() + "crumbIssuer/api/json";
        try (CloseableHttpResponse response = client.execute(new HttpGet(url))) {
            assertEquals("crumb acquisition must succeed", 200, response.getStatusLine().getStatusCode());
            return JSONObject.fromObject(EntityUtils.toString(response.getEntity()));
        }
    }

    private static void patterns(String... patterns) {
        PluginImpl.getInstance().setMachinePrincipalPatterns(Arrays.asList(patterns));
    }

    private void fakePrincipal(String principal) throws Exception {
        KerberosAuthenticator mockAuthenticator = mock(KerberosAuthenticator.class);
        authenticator = mockAuthenticator;
        when(mockAuthenticator.authenticate(any(HttpServletRequest.class), any(HttpServletResponse.class)))
                .thenAnswer(invocation -> {
                    if (!ticketAvailable) {
                        HttpServletResponse response = invocation.getArgument(1);
                        response.setHeader("WWW-Authenticate", "Negotiate");
                        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                        return null;
                    }
                    return new KerberosPrincipal(principal);
                });
        filter = new KerberosSSOFilter(Collections.emptyMap(), config -> mockAuthenticator);
        PluginServletFilter.addFilter(filter);
        // Publish the same filter the plugin lifecycle normally registers, retaining the mock KDC boundary.
        Field activeFilter = PluginImpl.class.getDeclaredField("filter");
        activeFilter.setAccessible(true);
        activeFilter.set(PluginImpl.getInstance(), filter);
        PluginImpl.getInstance().setEnabled(true);
    }
}
