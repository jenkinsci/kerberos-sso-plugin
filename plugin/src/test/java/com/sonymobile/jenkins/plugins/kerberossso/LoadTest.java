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

import hudson.FilePath;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.recipes.LocalData;

import java.io.File;

import static hudson.Functions.isWindows;
import static org.junit.Assert.assertEquals;
import static org.junit.Assume.assumeFalse;

public class LoadTest {

    private static final String LOGIN_CONF_PATH = "/tmp/kerberos-sso.login.conf";
    private static final String KRB5_CONF_PATH = "/tmp/kerberos-sso.krb5.conf";

    @Rule public JenkinsRule rule = new JenkinsRule();

    @BeforeClass
    public static void setUp() throws Exception {
        assumeFalse(isWindows());
        new FilePath(new File(LOGIN_CONF_PATH)).copyFrom(JcascTest.class.getResourceAsStream("test-login.conf"));
        new FilePath(new File(KRB5_CONF_PATH)).copyFrom(JcascTest.class.getResourceAsStream("test-krb5.conf"));
    }

    @Test
    @LocalData("oldXmlPath")
    public void oldXmlPath() {
        PluginImpl instance = PluginImpl.getInstance();
        assertEquals("/tmp/kerberos-sso.krb5.conf", instance.getKrb5Location());
        instance.registerFilter();
    }

    @Test
    @LocalData("newXmlPath")
    public void newXmlPath() {
        PluginImpl instance = PluginImpl.getInstance();
        assertEquals("/tmp/kerberos-sso.krb5.conf", instance.getKrb5Location());
    }
}
