package com.sonymobile.jenkins.plugins.kerberossso;

import hudson.security.ACL;
import hudson.security.ACLContext;
import hudson.security.SecurityRealm;
import jenkins.model.Jenkins;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Spike for R1 of the machine principal design: does a non-anonymous authentication inherit
 * permissions granted to the "authenticated" group even when it does not carry that authority?
 *
 * The whole deny-by-default trust model depends on the answer being no.
 */
public class MachineIdentitySpikeTest {

    // CS IGNORE VisibilityModifier FOR NEXT 2 LINES. REASON: JenkinsRule.
    @Rule
    public JenkinsRule j = new JenkinsRule();

    /** What the design proposes to mint: a machine name plus exactly one group authority. */
    private static Authentication machineToken() {
        return new UsernamePasswordAuthenticationToken("host/agent01.example.com", "",
                List.of(new SimpleGrantedAuthority("kerberos-machines")));
    }

    /** What a real security realm produces: the realm's own "authenticated" authority. */
    private static Authentication realUserToken() {
        return new UsernamePasswordAuthenticationToken("alice", "",
                Collections.singletonList(SecurityRealm.AUTHENTICATED_AUTHORITY2));
    }

    @Test
    public void machineTokenDoesNotInheritAuthenticatedGroupGrants() {
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        j.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy()
                .grant(Jenkins.READ).everywhere().toAuthenticated());

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
        j.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy()
                .grant(Jenkins.READ).everywhere().to("kerberos-machines"));

        try (ACLContext ignored = ACL.as2(machineToken())) {
            assertTrue("explicit group grant should apply", j.jenkins.hasPermission(Jenkins.READ));
            assertFalse("nothing else should be granted", j.jenkins.hasPermission(Jenkins.ADMINISTER));
        }
    }
}
