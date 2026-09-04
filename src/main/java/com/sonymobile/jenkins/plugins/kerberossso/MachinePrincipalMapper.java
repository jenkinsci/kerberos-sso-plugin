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
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Maps Kerberos machine principals to Jenkins identities.
 *
 * A machine is recognised by the shape of its principal: {@code host/fqdn@REALM} as issued from a
 * Unix keytab, or {@code NAME$@REALM} for a Windows computer account. Machines never go through the
 * security realm's user lookup. They are admitted only when they match a configured pattern, and
 * they authenticate as themselves carrying the single group {@link #GROUP}.
 *
 * The token deliberately lacks {@code SecurityRealm.AUTHENTICATED_AUTHORITY2}. Grants to the
 * "authenticated" group are matched by that authority, so leaving it off is what stops machines from
 * inheriting permissions meant for people. Do not add it.
 */
final class MachinePrincipalMapper {

    /** Group every admitted machine belongs to, the sid operators grant permissions to. */
    static final String GROUP = "kerberos-machines";

    private static final String DENY = "!";

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
     * Decide whether a machine may authenticate and as whom.
     *
     * A deny entry ({@code !pattern}) wins over any allow entry, so one machine can be revoked from a
     * glob that admits its peers.
     *
     * @param principalName Machine principal, realm included.
     * @param patterns Normalized patterns, see {@link #normalize}.
     * @return The machine's authentication, or null when it is not allowlisted.
     */
    static @CheckForNull Authentication map(@NonNull String principalName, @NonNull List<String> patterns) {
        String subject = principalName.toLowerCase(Locale.ROOT);
        boolean allowed = false;
        for (String pattern : patterns) {
            boolean deny = pattern.startsWith(DENY);
            if (globMatches(deny ? pattern.substring(DENY.length()) : pattern, subject)) {
                if (deny) {
                    return null;
                }
                allowed = true;
            }
        }
        if (!allowed) {
            return null;
        }
        return new UsernamePasswordAuthenticationToken(
                subject, "", Collections.singletonList(new SimpleGrantedAuthority(GROUP)));
    }

    /**
     * Bring configured patterns into the form {@link #map} expects.
     *
     * @param patterns Raw patterns, possibly null.
     * @return Trimmed, lowercased, deduplicated patterns with blanks dropped.
     * @throws IllegalArgumentException for a pattern without a realm. Matching is realm inclusive by
     *         design, so a realm-less pattern would admit any realm's machines; refuse it outright.
     */
    static @NonNull List<String> normalize(@CheckForNull List<String> patterns) {
        List<String> normalized = new ArrayList<>();
        if (patterns == null) {
            return normalized;
        }
        for (String raw : patterns) {
            String pattern = Util.fixEmptyAndTrim(raw);
            if (pattern == null) {
                continue;
            }
            pattern = pattern.toLowerCase(Locale.ROOT);
            String glob = pattern.startsWith(DENY) ? pattern.substring(DENY.length()) : pattern;
            if (!glob.contains("@")) {
                throw new IllegalArgumentException("Machine principal pattern must name a realm: " + raw);
            }
            if (!normalized.contains(pattern)) {
                normalized.add(pattern);
            }
        }
        return normalized;
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
