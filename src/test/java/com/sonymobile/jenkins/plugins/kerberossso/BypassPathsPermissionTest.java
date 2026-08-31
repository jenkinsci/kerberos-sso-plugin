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

import hudson.model.User;
import hudson.security.ACL;
import hudson.security.ACLContext;
import jenkins.model.Jenkins;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;

import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

/**
 * Permission checks on the bypass path accessors.
 *
 * These exist because the rest of the suite runs with {@code AuthorizationStrategy.UNSECURED}, where
 * anonymous holds ADMINISTER, so it cannot tell a working permission check from a missing one.
 */
public class BypassPathsPermissionTest {

    private static final List<String> LOGIN = Collections.singletonList("/login");

    // CS IGNORE VisibilityModifier FOR NEXT 2 LINES. REASON: JenkinsRule.
    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Before
    public void secureJenkins() {
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        j.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy()
                .grant(Jenkins.ADMINISTER).everywhere().to("alice")
                .grant(Jenkins.SYSTEM_READ, Jenkins.READ).everywhere().to("auditor")
                .grant(Jenkins.READ).everywhere().to("bob"));
    }

    @Test
    public void administratorCanConfigureBypassPaths() {
        try (ACLContext ignored = ACL.as2(user("alice"))) {
            PluginImpl.getInstance().setBypassPaths(LOGIN);
            assertEquals(LOGIN, PluginImpl.getInstance().getBypassPaths());
            assertEquals("/login", PluginImpl.getInstance().getBypassPathsString());
        }
    }

    @Test
    public void plainUserCannotConfigureBypassPaths() {
        try (ACLContext ignored = ACL.as2(user("bob"))) {
            assertThrows(AccessDeniedException.class, () -> PluginImpl.getInstance().setBypassPaths(LOGIN));
        }
    }

    @Test
    public void plainUserCannotReadBypassPathsFromTheConfigurationForm() {
        try (ACLContext ignored = ACL.as2(user("bob"))) {
            assertThrows(AccessDeniedException.class, () -> PluginImpl.getInstance().getBypassPathsString());
        }
    }

    @Test
    public void systemReaderCanViewButNotConfigure() {
        try (ACLContext ignored = ACL.as2(user("auditor"))) {
            PluginImpl.getInstance().getBypassPathsString();
            assertThrows(AccessDeniedException.class, () -> PluginImpl.getInstance().setBypassPaths(LOGIN));
        }
    }

    /**
     * The filter consults the paths for every request, anonymous ones included, so this accessor must
     * stay reachable without permission. Guarding it would reject the traffic the option governs.
     */
    @Test
    public void filterCanReadBypassPathsAnonymously() {
        try (ACLContext ignored = ACL.as2(user("alice"))) {
            PluginImpl.getInstance().setBypassPaths(LOGIN);
        }
        try (ACLContext ignored = ACL.as2(Jenkins.ANONYMOUS2)) {
            assertEquals(LOGIN, PluginImpl.getInstance().getBypassPaths());
        }
    }

    private static Authentication user(String name) {
        return User.getById(name, true).impersonate2();
    }
}
