package com.sonymobile.jenkins.plugins.kerberossso;

import hudson.security.ACL;
import hudson.security.ACLContext;
import hudson.security.GlobalMatrixAuthorizationStrategy;
import hudson.security.SecurityRealm;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.matrixauth.PermissionEntry;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.util.Collections;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Production Matrix Authorization checks using the actual machine mapper, with a human control.
 */
public class MachineAuthorizationTest {

    // CS IGNORE VisibilityModifier FOR NEXT 2 LINES. REASON: JenkinsRule.
    @Rule
    public JenkinsRule j = new JenkinsRule();

    /** The mapper must mint: a machine name plus exactly one group authority. */
    private static Authentication machineToken() {
        return MachinePrincipalMapper.map("host/agent01.example.com@EXAMPLE.COM",
                MachinePrincipalMapper.normalize(Collections.singletonList("host/*@EXAMPLE.COM")));
    }

    /** What a real security realm produces: the realm's own "authenticated" authority. */
    private static Authentication realUserToken() {
        return new UsernamePasswordAuthenticationToken("alice", "",
                Collections.singletonList(SecurityRealm.AUTHENTICATED_AUTHORITY2));
    }

    @Test
    public void machineTokenDoesNotInheritAuthenticatedGroupGrants() {
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        GlobalMatrixAuthorizationStrategy strategy = new GlobalMatrixAuthorizationStrategy();
        strategy.add(Jenkins.READ, PermissionEntry.group("authenticated"));
        j.jenkins.setAuthorizationStrategy(strategy);

        try (ACLContext ignored = ACL.as2(realUserToken())) {
            assertTrue("control: a realm-issued token should hold the authenticated grant",
                    j.jenkins.hasPermission(Jenkins.READ));
        }

        try (ACLContext ignored = ACL.as2(machineToken())) {
            assertFalse("MACHINE TOKEN MUST NOT INHERIT 'authenticated' GRANTS",
                    j.jenkins.hasPermission(Jenkins.READ));
        }
    }

    @Test
    public void machineTokenHoldsOnlyWhatIsGrantedToItsOwnGroup() {
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        GlobalMatrixAuthorizationStrategy strategy = new GlobalMatrixAuthorizationStrategy();
        strategy.add(Jenkins.READ, PermissionEntry.group("kerberos-machines"));
        j.jenkins.setAuthorizationStrategy(strategy);

        try (ACLContext ignored = ACL.as2(machineToken())) {
            assertTrue("explicit group grant should apply", j.jenkins.hasPermission(Jenkins.READ));
            assertFalse("nothing else should be granted", j.jenkins.hasPermission(Jenkins.ADMINISTER));
        }
    }
}
