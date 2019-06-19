/*
 * The MIT License
 *
 * Copyright (c) Red Hat, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package com.sonymobile.jenkins.plugins.kerberossso;

import com.google.common.collect.Maps;
import com.google.common.io.Resources;
import hudson.Util;
import io.jenkins.plugins.casc.ConfigurationAsCode;
import io.jenkins.plugins.casc.ConfiguratorException;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import io.jenkins.plugins.casc.yaml.YamlSource;
import org.apache.tools.ant.filters.StringInputStream;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static java.util.Collections.emptyMap;
import static org.junit.Assert.*;
import static org.junit.Assert.assertEquals;

public class JcascTest {

    @Rule
    public JenkinsConfiguredWithCodeRule j = new JenkinsConfiguredWithCodeRule();

    private String krb5conf;
    private String loginConf;

    @Before
    public void before() throws Exception {
        krb5conf = new File(JcascTest.class.getResource("JcascTest/test-krb5.conf").toURI()).getAbsolutePath();
        loginConf = new File(JcascTest.class.getResource("JcascTest/test-login.conf").toURI()).getAbsolutePath();
    }

    @Test
    public void populate() throws Exception {
        PluginImpl i = PluginImpl.getInstance();
        assertNull(i.getFilter());
        applyConfig(getJcascYaml("full", Collections.singletonMap("REDIRECT", "acme.com")));

        assertTrue(i.getEnabled());
        assertEquals("foo", i.getAccountName());
        assertEquals("bar", i.getPassword().getPlainText());
        assertEquals("acme.com", i.getRedirect());
        assertTrue(i.isRedirectEnabled());
        assertEquals(krb5conf, i.getKrb5Location());
        assertEquals(loginConf, i.getLoginLocation());
        assertEquals("spnego-server", i.getLoginServerModule());
        assertEquals("spnego-client", i.getLoginClientModule());
        assertTrue(i.getAnonymousAccess());
        assertFalse(i.isAllowLocalhost());
        assertFalse(i.isAllowBasic());
        assertTrue(i.isAllowDelegation());
        assertFalse(i.isAllowUnsecureBasic());
        assertFalse(i.isPromptNtlm());
        assertNotNull(PluginImpl.getInstance().getFilter());

        // Verify Servlet filter gets updated when config changes
        KerberosSSOFilter oldFilter = i.getFilter();
        applyConfig(getJcascYaml("full", Collections.singletonMap("REDIRECT", "foo.com")));
        assertNotSame(PluginImpl.getInstance().getFilter(), oldFilter);
        assertNotNull(PluginImpl.getInstance().getFilter());
    }

    @Test
    public void minimal() throws Exception {
        applyConfig(getJcascYaml("minimal"));

        PluginImpl i = PluginImpl.getInstance();
        assertTrue(i.getEnabled());
        assertEquals("Service account", i.getAccountName());
        assertEquals("", i.getPassword().getPlainText());
        assertFalse(i.isRedirectEnabled());

        assertEquals(krb5conf, i.getKrb5Location());
        assertEquals(loginConf, i.getLoginLocation());
        assertEquals("spnego-server", i.getLoginServerModule());
        assertEquals("spnego-client", i.getLoginClientModule());
        assertFalse(i.getAnonymousAccess());
        assertTrue(i.isAllowLocalhost());
        assertTrue(i.isAllowBasic());
        assertFalse(i.isAllowDelegation());
        assertTrue(i.isAllowUnsecureBasic());
        assertFalse(i.isPromptNtlm());
        assertNotNull(PluginImpl.getInstance().getFilter());
    }

    @Test
    public void off() throws Exception {
        applyConfig(getJcascYaml("off"));

        PluginImpl i = PluginImpl.getInstance();
        assertFalse(i.getEnabled());
        assertNull(i.getFilter());
    }

    private String getJcascYaml(String jcasc) throws IOException, URISyntaxException {
        return getJcascYaml(jcasc, emptyMap());
    }

    private String getJcascYaml(String jcasc, Map<String, String> custom) throws IOException, URISyntaxException {
        HashMap<String, String> vars = Maps.newHashMap();
        vars.put("KRB5_CONF", krb5conf);
        vars.put("LOGIN_CONF", loginConf);
        vars.putAll(custom);

        String name = "JcascTest/" + jcasc + ".yaml";
        URL resource = getClass().getResource(name);
        if (resource == null) throw new Error("Unable to find resource " + name);
        String raw = Resources.toString(resource.toURI().toURL(), Charset.defaultCharset());
        return Util.replaceMacro(raw, vars);
    }

    private void applyConfig(String jcasc) throws ConfiguratorException {
        ConfigurationAsCode.get().configureWith(YamlSource.of(new StringInputStream(jcasc)));
    }
}
