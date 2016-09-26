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

import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * UI tests for the global configuration page of the plugin.
 * @author Joakim Ahle &lt;joakim.ahle@sonyericsson.com&gt;
 */
public class KerberosConfigTest {

    /**
     * Jenkins rule instance.
     */
    // CS IGNORE VisibilityModifier FOR NEXT 3 LINES. REASON: Mocks tests.
    @Rule
    public JenkinsRule rule = new JenkinsRule();
    private JenkinsRule.WebClient webClient;
    private HtmlPage currentPage;

    /**
     * Sets up a a web client that navigates to the global config page.
     * @throws Exception if something goes wrong
     */
    @Before
    public void setUp() throws Exception {
        webClient = rule.createWebClient();
        currentPage = webClient.goTo("configure");
    }

    /**
     * Tests if the PluginImpl class changes attributes if a new config is submitted.
     */
    @Test
    public void testIfConfigCanBeUpdated() throws Exception {
        assertFalse("Plugin already enabled", PluginImpl.getInstance().getEnabled());

        String loginConf = getClass().getResource("login.conf").getFile();

        HtmlForm form = currentPage.getFormByName("config");

        form.getInputByName("_.enabled").click();
        form.getInputByName("_.account").setValueAttribute("account");
        form.getInputByName("_.password").setValueAttribute("pwd");
        form.getInputByName("_.loginLocation").setValueAttribute(loginConf);
        form.getInputByName("_.krb5Location").setValueAttribute("/etc/krb5.conf");
        form.getInputByName("_.loginServerModule").setValueAttribute("spnego-server");
        form.getInputByName("_.loginClientModule").setValueAttribute("spnego-client");


        form.getInputByName("_.allowLocalhost").setAttribute("checked", "true");
        form.getInputByName("_.allowBasic").removeAttribute("checked");
        form.getInputByName("_.allowUnsecureBasic").removeAttribute("checked");
        form.getInputByName("_.allowDelegation").setAttribute("checked", "true");
        form.getInputByName("_.promptNtlm").removeAttribute("checked");

        rule.submit(form);

        PluginImpl plugin = PluginImpl.getInstance();
        assertTrue("Plugin wasn't enabled after saving the new config", plugin.getEnabled());
        assertEquals("account", plugin.getAccountName());
        assertEquals("pwd", plugin.getPassword().getPlainText());
        assertEquals(loginConf, plugin.getLoginLocation());
        assertEquals("/etc/krb5.conf", plugin.getKrb5Location());
        assertEquals("spnego-server", plugin.getLoginServerModule());
        assertEquals("spnego-client", plugin.getLoginClientModule());
    }
}
