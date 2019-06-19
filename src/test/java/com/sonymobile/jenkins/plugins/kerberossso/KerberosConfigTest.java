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

import com.gargoylesoftware.htmlunit.html.HtmlCheckBoxInput;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlInput;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import org.codelibs.spnego.SpnegoHttpFilter;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runners.model.Statement;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.RestartableJenkinsRule;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * UI tests for the global configuration page of the plugin.
 */
public class KerberosConfigTest {

    // CS IGNORE VisibilityModifier FOR NEXT 3 LINES. REASON: Mocks tests.
    @Rule
    public RestartableJenkinsRule r = new RestartableJenkinsRule();

    /**
     * Tests if the PluginImpl class changes attributes if a new config is submitted.
     */
    @Test
    public void configRoundtrip() {
        final String loginConf = getClass().getResource("login.conf").getFile();

        r.addStep(new Statement() {
            // Configure
            @Override public void evaluate() throws Throwable {
                checkDisabled();

                HtmlPage currentPage = r.j.createWebClient().goTo("configureSecurity");
                HtmlForm form = currentPage.getFormByName("config");

                form.getInputByName("_.enabled").click();
                form.getInputByName("_.account").setValueAttribute("account");
                form.getInputByName("_.password").setValueAttribute("pwd");
                form.getInputByName("_.loginLocation").setValueAttribute(loginConf);
                form.getInputByName("_.krb5Location").setValueAttribute("/etc/krb5.conf");
                form.getInputByName("_.loginServerModule").setValueAttribute("spnego-server");
                form.getInputByName("_.loginClientModule").setValueAttribute("spnego-client");

                check(form.getInputByName("_.anonymousAccess"), true);
                check(form.getInputByName("_.allowLocalhost"), true);
                check(form.getInputByName("_.allowBasic"), false);
                check(form.getInputByName("_.allowUnsecureBasic"), false);
                check(form.getInputByName("_.allowDelegation"), true);
                check(form.getInputByName("_.promptNtlm"), false);

                r.j.submit(form);

                checkConfig(loginConf);
                checkEnabled();
            }
        });
        r.addStep(new Statement() {
            @Override public void evaluate() throws Throwable {

                // Recheck after restart
                checkConfig(loginConf);
                checkEnabled();

                // Reconfigure disable
                JenkinsRule.WebClient wc = r.j.createWebClient();
                HtmlPage currentPage = wc.goTo("configureSecurity");
                HtmlForm form = currentPage.getFormByName("config");
                form.getInputByName("_.enabled").click();
                r.j.submit(form);

                checkConfig(loginConf);
                checkDisabled();

                // Check config update propagated
                currentPage = wc.goTo("configureSecurity");
                form = currentPage.getFormByName("config");
                form.getInputByName("_.enabled").click();
                form.getInputByName("_.krb5Location").setValueAttribute("/foo");
                r.j.submit(form);
                KerberosSSOFilter filter = PluginImpl.getInstance().getFilter();
                assertEquals("/foo", filter.config.get(SpnegoHttpFilter.Constants.KRB5_CONF));
            }
        });
    }

    private void checkConfig(String loginConf) {
        PluginImpl plugin = PluginImpl.getInstance();

        assertEquals("account", plugin.getAccountName());
        assertEquals("pwd", plugin.getPassword().getPlainText());
        assertEquals(loginConf, plugin.getLoginLocation());
        assertEquals("/etc/krb5.conf", plugin.getKrb5Location());
        assertEquals("spnego-server", plugin.getLoginServerModule());
        assertEquals("spnego-client", plugin.getLoginClientModule());

        assertTrue("Anonymous enabled", plugin.getAnonymousAccess());
        assertTrue("Localhost enabled", plugin.isAllowLocalhost());
        assertFalse("Basic disabled", plugin.isAllowBasic());
        assertFalse("Unsecured basic disabled", plugin.isAllowUnsecureBasic());
        assertTrue("Delegation allowed", plugin.isAllowDelegation());
        assertFalse("NTLM disabled", plugin.isPromptNtlm());
    }

    private void checkEnabled() {
        PluginImpl plugin = PluginImpl.getInstance();
        assertTrue("Plugin not enabled", plugin.getEnabled());
        KerberosSSOFilter filter = plugin.getFilter();
        assertNotNull("Plugin filter registered", filter);
        assertTrue("Plugin filter active", filter.isActive());
    }

    private void checkDisabled() {
        PluginImpl plugin = PluginImpl.getInstance();
        assertFalse("Plugin enabled", plugin.getEnabled());
        KerberosSSOFilter filter = plugin.getFilter();
        assertEquals("Plugin filter registered", null, filter);
    }

    /**
     * Test to verify that changes made programatically
     * are seen in the UI and are active.
     */
    @Test
    public void configProgrammatically() {
        final String loginConf = getClass().getResource("login.conf").getFile();
        r.addStep(new Statement() {
            // Configure
            @Override public void evaluate() throws Throwable {
                checkDisabled();

                HtmlPage currentPage = r.j.createWebClient().goTo("configureSecurity");
                HtmlForm form = currentPage.getFormByName("config");

                form.getInputByName("_.enabled").click();
                form.getInputByName("_.account").setValueAttribute("account");
                form.getInputByName("_.password").setValueAttribute("pwd");
                form.getInputByName("_.loginLocation").setValueAttribute(loginConf);
                form.getInputByName("_.krb5Location").setValueAttribute("/etc/krb5.conf");
                form.getInputByName("_.loginServerModule").setValueAttribute("spnego-server");
                form.getInputByName("_.loginClientModule").setValueAttribute("spnego-client");

                form.getInputByName("_.anonymousAccess").setAttribute("checked", "true");
                form.getInputByName("_.allowLocalhost").setAttribute("checked", "true");
                form.getInputByName("_.allowBasic").setAttribute("checked", "true");
                form.getInputByName("_.allowUnsecureBasic").setAttribute("checked", "true");
                form.getInputByName("_.allowDelegation").setAttribute("checked", "true");
                form.getInputByName("_.promptNtlm").removeAttribute("checked");

                r.j.submit(form);

                checkEnabled();

                PluginImpl.getInstance().setAllowBasic(true);
                PluginImpl.getInstance().setAllowLocalhost(false);
                PluginImpl.getInstance().setAllowUnsecureBasic(false);
                PluginImpl.getInstance().reconfigure();

                currentPage = r.j.createWebClient().goTo("configureSecurity");

                form = currentPage.getFormByName("config");
                assertTrue("allowBasic not true",
                        form.getInputByName("_.allowBasic").getAttribute("checked").equals("true"));
                assertFalse("allowLocalhost not checked",
                        form.getInputByName("_.allowLocalhost").hasAttribute("checked"));
                assertFalse("allowUnsecureBasic not checked",
                        form.getInputByName("_.allowUnsecureBasic").hasAttribute("checked"));
            }
        });
    }

    private static void check(HtmlInput input, boolean checked) {
        HtmlCheckBoxInput cb = (HtmlCheckBoxInput)input;
        cb.setChecked(checked);
    }
}
