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

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Util;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Maps Kerberos machine principals to Jenkins identities.
 *
 * A machine is recognised by the shape of its principal: {@code host/fqdn@REALM} as issued from a
 * Unix keytab, or {@code NAME$@REALM} for a Windows computer account. Machines never go through the
 * security realm's user lookup. They are admitted only when they match a configured pattern, and
 * they authenticate as themselves carrying {@link #GROUP} plus any groups their patterns name.
 *
 * A pattern is a glob, optionally followed by the groups to grant:
 * <pre>
 * host/*-laptop-*.example.com@EXAMPLE.COM -&gt; laptop-callbacks
 * host/deploy*.example.com@EXAMPLE.COM    -&gt; deploy-triggers, production
 * !decommissioned$@EXAMPLE.COM
 * </pre>
 * Groups let an authorization strategy grant one class of machine access to one job without
 * granting every machine the same. A machine matching several patterns receives the union of their
 * groups.
 *
 * The token deliberately lacks {@code SecurityRealm.AUTHENTICATED_AUTHORITY2}. Grants to the
 * "authenticated" group are matched by that authority, so leaving it off is what stops machines from
 * inheriting permissions meant for people. Do not add it.
 */
final class MachinePrincipalMapper {

    /** Group every admitted machine belongs to, whatever else its patterns name. */
    static final String GROUP = "kerberos-machines";

    private static final String DENY = "!";
    private static final String GROUPS = "->";

    private MachinePrincipalMapper() {
    }

    /**
     * @param principalName Principal as reported by the authenticator, realm included.
     * @return true for service and computer account principals, false for users.
     */
    static boolean isMachinePrincipal(@NonNull String principalName) {
        int at = principalName.indexOf('@');
        String local = at < 0 ? principalName : principalName.substring(0, at);
        return local.contains("/") || local.endsWith("$");
    }

    /**
     * Decide whether a machine may authenticate, as whom, and in which groups.
     *
     * A deny entry wins over every allow entry regardless of order, so one machine can be revoked
     * from a glob that admits its peers.
     *
     * @param principalName Machine principal, realm included.
     * @param patterns Normalized patterns, see {@link #normalize}.
     * @return The machine's authentication, or null when it is not allowlisted.
     */
    static @CheckForNull Authentication map(@NonNull String principalName, @NonNull List<String> patterns) {
        String subject = principalName.toLowerCase(Locale.ROOT);
        Set<String> groups = new LinkedHashSet<>();
        groups.add(GROUP);
        boolean allowed = false;

        for (String pattern : patterns) {
            boolean deny = pattern.startsWith(DENY);
            String body = deny ? pattern.substring(DENY.length()) : pattern;
            if (!globMatches(glob(body), subject)) {
                continue;
            }
            if (deny) {
                return null;
            }
            allowed = true;
            groups.addAll(groups(body));
        }

        if (!allowed) {
            return null;
        }

        List<GrantedAuthority> authorities = groups.stream()
                .map(SimpleGrantedAuthority::new).collect(Collectors.toList());
        return new UsernamePasswordAuthenticationToken(subject, "", authorities);
    }

    /**
     * Bring configured patterns into the form {@link #map} expects.
     *
     * The glob is lowercased to match the lowercased principal. Group names keep their case, because
     * authorization strategies match them literally.
     *
     * @param patterns Raw patterns, possibly null.
     * @return Canonical patterns, blanks and duplicates dropped.
     * @throws IllegalArgumentException for a glob without a realm, a deny entry naming groups, or an
     *         entry whose groups are empty. Matching is realm inclusive by design, so a realm-less
     *         glob would admit any realm's machines; refuse it outright.
     */
    static @NonNull List<String> normalize(@CheckForNull List<String> patterns) {
        List<String> normalized = new ArrayList<>();
        if (patterns == null) {
            return normalized;
        }
        for (String raw : patterns) {
            String entry = Util.fixEmptyAndTrim(raw);
            if (entry == null) {
                continue;
            }
            boolean deny = entry.startsWith(DENY);
            String body = deny ? entry.substring(DENY.length()) : entry;

            String glob = glob(body).toLowerCase(Locale.ROOT);
            if (glob.isEmpty()) {
                throw new IllegalArgumentException("Machine principal pattern is missing: " + raw);
            }
            if (!glob.contains("@")) {
                throw new IllegalArgumentException("Machine principal pattern must name a realm: " + raw);
            }

            List<String> groups = groups(body);
            if (deny && body.contains(GROUPS)) {
                throw new IllegalArgumentException("A deny pattern grants nothing, drop its groups: " + raw);
            }
            if (!deny && body.contains(GROUPS) && groups.isEmpty()) {
                throw new IllegalArgumentException("Machine principal pattern names no group after ->: " + raw);
            }

            String canonical = (deny ? DENY : "") + glob
                    + (groups.isEmpty() ? "" : " " + GROUPS + " " + String.join(", ", groups));
            if (!normalized.contains(canonical)) {
                normalized.add(canonical);
            }
        }
        return normalized;
    }

    /** The glob part of a pattern body, before any {@code ->}. */
    private static @NonNull String glob(@NonNull String body) {
        int arrow = body.indexOf(GROUPS);
        return (arrow < 0 ? body : body.substring(0, arrow)).trim();
    }

    /** The groups named after {@code ->}, in order, blanks dropped. Case preserved. */
    private static @NonNull List<String> groups(@NonNull String body) {
        int arrow = body.indexOf(GROUPS);
        if (arrow < 0) {
            return new ArrayList<>();
        }
        List<String> groups = new ArrayList<>();
        for (String group : body.substring(arrow + GROUPS.length()).split(",")) {
            String name = Util.fixEmptyAndTrim(group);
            if (name != null && !groups.contains(name)) {
                groups.add(name);
            }
        }
        return groups;
    }

    /**
     * Match with {@code *} as the only wildcard. Everything else is literal, so there is no regex
     * surface for operators to get wrong.
     */
    static boolean globMatches(@NonNull String glob, @NonNull String value) {
        String[] literals = glob.split("\\*", -1);
        StringBuilder regex = new StringBuilder();
        for (int i = 0; i < literals.length; i++) {
            if (i > 0) {
                regex.append(".*");
            }
            regex.append(Pattern.quote(literals[i]));
        }
        return Pattern.compile(regex.toString(), Pattern.CASE_INSENSITIVE).matcher(value).matches();
    }
}
