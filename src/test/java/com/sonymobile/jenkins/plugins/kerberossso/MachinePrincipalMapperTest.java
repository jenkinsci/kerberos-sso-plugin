package com.sonymobile.jenkins.plugins.kerberossso;

import org.junit.Test;
import org.springframework.security.core.Authentication;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static com.sonymobile.jenkins.plugins.kerberossso.MachinePrincipalMapper.GROUP;
import static com.sonymobile.jenkins.plugins.kerberossso.MachinePrincipalMapper.globMatches;
import static com.sonymobile.jenkins.plugins.kerberossso.MachinePrincipalMapper.isMachinePrincipal;
import static com.sonymobile.jenkins.plugins.kerberossso.MachinePrincipalMapper.map;
import static com.sonymobile.jenkins.plugins.kerberossso.MachinePrincipalMapper.normalize;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

/** Pure unit tests for the mapper, no Jenkins needed. */
public class MachinePrincipalMapperTest {

    @Test
    public void recognisesServiceAndComputerAccountPrincipals() {
        assertTrue(isMachinePrincipal("host/a.example.com@EXAMPLE.COM"));
        assertTrue(isMachinePrincipal("HTTP/jenkins.example.com@EXAMPLE.COM"));
        assertTrue(isMachinePrincipal("AGENT01$@EXAMPLE.COM"));
        assertFalse(isMachinePrincipal("alice@EXAMPLE.COM"));
        assertFalse(isMachinePrincipal("alice"));
        assertFalse("a $ only marks a computer account at the end of the name",
                isMachinePrincipal("a$b@EXAMPLE.COM"));
    }

    @Test
    public void starIsTheOnlyWildcardAndEverythingElseIsLiteral() {
        assertTrue(globMatches("host/*@example.com", "host/a.b.example.com@example.com"));
        assertTrue(globMatches("*$@example.com", "agent01$@example.com"));
        assertFalse("must match the whole value",
                globMatches("host/a.example.com@example.com", "host/a.example.com@example.com.evil"));
        assertFalse("dots are literal, not regex",
                globMatches("host/a.example.com@example.com", "host/aXexampleYcom@example.com"));
        assertTrue(globMatches("HOST/*@EXAMPLE.COM", "host/a@example.com"));
    }

    @Test
    public void normalizeLowercasesTrimsAndDeduplicates() {
        assertEquals(Arrays.asList("host/*@example.com", "!agent01$@example.com"),
                normalize(Arrays.asList("  HOST/*@EXAMPLE.COM ", "", null, "host/*@example.com", "!AGENT01$@EXAMPLE.COM")));
    }

    @Test
    public void normalizeRejectsPatternsWithoutARealm() {
        assertThrows(IllegalArgumentException.class, () -> normalize(Collections.singletonList("host/*")));
        assertThrows(IllegalArgumentException.class, () -> normalize(Collections.singletonList("*")));
        assertThrows(IllegalArgumentException.class, () -> normalize(Collections.singletonList("!")));
    }

    @Test
    public void denyWinsRegardlessOfOrder() {
        List<String> denyFirst = normalize(Arrays.asList("!agent01$@example.com", "*$@example.com"));
        List<String> denyLast = normalize(Arrays.asList("*$@example.com", "!agent01$@example.com"));
        assertNull(map("AGENT01$@EXAMPLE.COM", denyFirst));
        assertNull(map("AGENT01$@EXAMPLE.COM", denyLast));
        assertNotNull(map("AGENT02$@EXAMPLE.COM", denyLast));
    }

    @Test
    public void mappedTokenIsTheLowercasedPrincipalWithOnlyTheMachineGroup() {
        Authentication a = map("HOST/A.Example.com@EXAMPLE.COM", normalize(Collections.singletonList("host/*@example.com")));
        assertNotNull(a);
        assertEquals("host/a.example.com@example.com", a.getName());
        assertEquals(1, a.getAuthorities().size());
        assertEquals(GROUP, a.getAuthorities().iterator().next().getAuthority());
    }

    @Test
    public void nothingConfiguredAdmitsNothing() {
        assertNull(map("host/a@example.com", Collections.emptyList()));
    }
}
