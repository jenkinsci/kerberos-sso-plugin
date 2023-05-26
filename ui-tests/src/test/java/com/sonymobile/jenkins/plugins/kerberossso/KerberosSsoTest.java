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

import com.google.inject.Inject;
import java.util.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.impl.auth.BasicSchemeFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.jenkinsci.test.acceptance.docker.Docker;
import org.jenkinsci.test.acceptance.docker.DockerContainerHolder;
import org.jenkinsci.test.acceptance.guice.TestCleaner;
import org.jenkinsci.test.acceptance.junit.AbstractJUnitTest;
import org.jenkinsci.test.acceptance.junit.DockerTest;
import org.jenkinsci.test.acceptance.junit.FailureDiagnostics;
import org.jenkinsci.test.acceptance.junit.WithDocker;
import org.jenkinsci.test.acceptance.junit.WithPlugins;
import org.jenkinsci.test.acceptance.plugins.configuration_as_code.JcascManage;
import org.jenkinsci.test.acceptance.po.GlobalSecurityConfig;
import org.jenkinsci.test.acceptance.po.JenkinsDatabaseSecurityRealm;
import org.jenkinsci.test.acceptance.po.PageAreaImpl;
import org.jenkinsci.test.acceptance.po.User;
import org.jenkinsci.test.acceptance.utils.IOUtil;
import org.jenkinsci.utils.process.ProcessInputStream;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.model.Statement;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.firefox.FirefoxOptions;
import org.openqa.selenium.firefox.FirefoxProfile;
import org.openqa.selenium.remote.RemoteWebDriver;
import org.openqa.selenium.remote.UnreachableBrowserException;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.jenkinsci.test.acceptance.Matchers.containsRegexp;
import static org.junit.Assert.assertEquals;

/**
 * Run Kerberos SSO tests against the containerized KDC.
 */
@WithPlugins({"kerberos-sso", "mailer"})
@Category(DockerTest.class)
@WithDocker
public class KerberosSsoTest extends AbstractJUnitTest {
    private static final Logger LOGGER = Logger.getLogger(KerberosSsoTest.class.getName());
    private static final String AUTHORIZED = "user.{1,20}IsAuthenticated\\?:.{1,20}true.{1,20}Authorities:.{1,20}\"authenticated\"";

    @Inject
    public DockerContainerHolder<KerberosContainer> kerberos;

    @Inject
    public FailureDiagnostics diag;

    @Inject
    public TestCleaner cleaner;

    @Test
    public void kerberosTicket() throws Exception {
        setupRealmUser();
        KerberosContainer kdc = startKdc();
        configureSsoUsingPos(kdc, false, false);

        verifyTicketAuth(kdc);

        // The global driver is not configured to do so
        driver.manage().deleteAllCookies(); // Logout
        jenkins.visit("/whoAmI"); // 401 Unauthorized
        assertThat(driver.getPageSource(), not(containsRegexp(AUTHORIZED)));
    }

    @Test
    public void kerberosTicketWithBasicAuthEnabled() throws Exception {
        setupRealmUser();
        KerberosContainer kdc = startKdc();
        configureSsoUsingPos(kdc, false, true);

        verifyTicketAuth(kdc);
    }

    @Test
    public void kerberosTicketWithBasicAuthEnabledJcasc() throws Exception {
        setupRealmUser();
        KerberosContainer kdc = startKdc();
        configureSsoUsingJcasc(kdc, false, true);

        verifyTicketAuth(kdc);
    }

    private void verifyTicketAuth(KerberosContainer kdc) throws IOException {
        // Correctly negotiate in browser
        WebDriver negotiatingDriver = getNegotiatingFirefox(kdc);

        //visit the page who requires authorization and asks for credentials before visiting unprotected root action "/whoAmI"
        negotiatingDriver.get(jenkins.url.toExternalForm());

        negotiatingDriver.get(jenkins.url("/whoAmI").toExternalForm());
        String out = negotiatingDriver.getPageSource();
        assertThat(out, containsRegexp(AUTHORIZED));

        // Non-negotiating request should fail
        assertUnauthenticatedRequestIsRejected(getBadassHttpClient());
    }

    @Test
    public void basicAuth() throws Exception {
        setupRealmUser();
        KerberosContainer kdc = startKdc();
        configureSsoUsingPos(kdc, false, true);

        CloseableHttpClient httpClient = getBadassHttpClient();

        // No credentials provided
        assertUnauthenticatedRequestIsRejected(httpClient);

        // Correct credentials provided
        HttpGet get = new HttpGet(jenkins.url.toExternalForm() + "/whoAmI");
        get.setHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString("user:ATH".getBytes()));
        CloseableHttpResponse response = httpClient.execute(get);
        String phrase = response.getStatusLine().getReasonPhrase();
        String out = IOUtils.toString(response.getEntity().getContent(),Charset.defaultCharset());
        assertThat(phrase + ": " + out, out, containsString("Full User Name"));
        assertThat(phrase + ": " + out, out, containsString("redacted for security reasons"));
        assertThat(phrase + ": " + out, out, containsRegexp("Authorities:.{1,50}\"authenticated\""));
        assertEquals(phrase + ": " + out, "OK", phrase);

        //reset client
        httpClient = getBadassHttpClient();
        // Incorrect credentials provided
        get = new HttpGet(jenkins.url.toExternalForm() + "/whoAmI");
        get.setHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString("user:WRONG_PASSWD".getBytes()));
        response = httpClient.execute(get);
        response.getEntity().writeTo(System.err);
        assertEquals("Unauthorized", response.getStatusLine().getReasonPhrase());
    }

    @Test
    public void explicitTicketAuth() throws Exception {
        setupRealmUser();
        KerberosContainer kdc = startKdc();
        configureSsoUsingPos(kdc, true, true);

        WebDriver nego = getNegotiatingFirefox(kdc);

        assertNegotiationWorking(nego);
    }

    private void assertNegotiationWorking(WebDriver nego) {
        nego.get(jenkins.url("/whoAmI").toExternalForm());
        assertThat(nego.getPageSource(), not(containsRegexp(AUTHORIZED)));

        nego.get(jenkins.url("/login").toExternalForm());
        nego.get(jenkins.url("/whoAmI").toExternalForm());
        assertThat(nego.getPageSource(), containsRegexp(AUTHORIZED));
    }

    @Test
    public void explicitBasicAuth() throws Exception {
        setupRealmUser();
        KerberosContainer kdc = startKdc();
        configureSsoUsingPos(kdc, true, true);

        assertAnonymousWithoutCredentials();
        assertLoggedInWithCorrectCredentials();
        assertRejectedWithIncorrectCredentials();
    }

    private void assertRejectedWithIncorrectCredentials() throws IOException {
        HttpGet get = new HttpGet(jenkins.url.toExternalForm() + "/login");
        get.setHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString("user:WRONG_PASSWD".getBytes()));
        CloseableHttpResponse response = getBadassHttpClient().execute(get);
        assertEquals("Unauthorized", response.getStatusLine().getReasonPhrase());
    }

    private void assertLoggedInWithCorrectCredentials() throws IOException {
        HttpGet get = new HttpGet(jenkins.url.toExternalForm() + "/login");
        get.setHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString("user:ATH".getBytes()));
        CloseableHttpResponse response = getBadassHttpClient().execute(get);
        String phrase = response.getStatusLine().getReasonPhrase();
        String out = IOUtils.toString(response.getEntity().getContent(),Charset.defaultCharset());
        assertThat(phrase + ": " + out, out, containsString("Full User Name"));
        //assertThat(phrase + ": " + out, out, containsRegexp("Authorities:.{1,50}\"authenticated\""));
        assertEquals(phrase + ": " + out, "OK", phrase);
    }

    private void assertAnonymousWithoutCredentials() throws IOException {
        HttpGet get = new HttpGet(jenkins.url.toExternalForm() + "/whoAmI");
        CloseableHttpResponse response = getBadassHttpClient().execute(get);
        String out = IOUtils.toString(response.getEntity().getContent(),Charset.defaultCharset());
        assertThat(out, not(containsRegexp("Authorities:.{1,50}\"authenticated\"")));
        assertThat(out, containsString("anonymous"));
    }

    private WebDriver getNegotiatingFirefox(KerberosContainer kdc) throws IOException {
        final String containerName = "selenium container for negotiation";
        final String image = "selenium/standalone-firefox:latest";

        try {
            Path log = diag.touch("negotiation-container-run.log").toPath();
            LOGGER.info("Starting " + containerName + ". Logs in " + log);

            int port = 4445;
            if (!IOUtil.isTcpPortFree(port)) throw new IllegalStateException("Port " + port + " is occupied");

            Docker.cmd("pull", image).popen().verifyOrDieWith("Failed to pull image " + image + " for " + containerName);

            List<String> args = new ArrayList<>(Arrays.asList(
                    "run", "-d", "--shm-size=2g", "--network=host",
                    "-v", diag.mkdirs("").getAbsolutePath() + ":/tmp/diagnostics",
                    "-v", kdc.getClientTokenCache() + ":/tmp/client_token_cache",
                    "-v", kdc.getKrb5ConfPath() + ":/tmp/krb5.conf"
            ));
            getBrowserEnvironment().forEach((n, v) -> { args.add("-e"); args.add(n + "=" + v); });
            args.add("-e"); args.add("SE_OPTS=-port " + port);
            args.add("-e"); args.add("DISPLAY=:1"); // Make sure this does not collide with primary selenium container for ATH (since they are using host net)
            args.add(image);

            ProcessInputStream popen = Docker.cmd(args.toArray(new String[0])).popen();
            popen.waitFor();
            String cid = popen.verifyOrDieWith("Failed to run " + containerName).trim();

            new ProcessBuilder(Docker.cmd("logs", "-f", cid).toCommandArray()).redirectErrorStream(true).redirectOutput(log.toFile()).start();

            Closeable cleanContainer = new Closeable() {
                @Override public void close() {
                    try { 
                        LOGGER.info("Cleaning " + cid + args.toArray(new String[0]));
                        Docker.cmd("ps").popen().verifyOrDieWith("Failed to rm " + cid);
                    } catch (IOException | InterruptedException e) {
                        throw new Error("Failed removing " + containerName, e);
                    }
                }

                @Override public String toString() {
                    return "Kill and remove " + containerName;
                }
            };
            Thread.sleep(3000);

            FirefoxProfile profile = new FirefoxProfile();
            profile.setAlwaysLoadNoFocusLib(true);

            String trustedUris = getTrustedUris();
            profile.setPreference("network.negotiate-auth.trusted-uris", trustedUris);
            profile.setPreference("network.negotiate-auth.delegation-uris", trustedUris);

            try {
                RemoteWebDriver remoteWebDriver = new RemoteWebDriver(new URL("http://127.0.0.1:" + port + "/wd/hub"), new FirefoxOptions().setProfile(profile));
                cleaner.addTask(cleanContainer);
                cleaner.addTask(new Statement() {
                    @Override
                    public void evaluate() {
                        try {
                            remoteWebDriver.quit();
                        } catch (UnreachableBrowserException ex) {
                            LOGGER.log(Level.WARNING, "Browser died already", ex);
                        }
                    }

                    @Override public String toString() {
                        return "Close Kerberos WebDriver after test";
                    }
                });
                return remoteWebDriver;
            } catch (RuntimeException e) {
                cleanContainer.close();
                throw e;
            } catch (Throwable e) {
                cleanContainer.close();
                throw new Error(e);
            }
        } catch (InterruptedException e) {
            throw new Error(e);
        }
    }

    private Map<String, String> getBrowserEnvironment() {
        Map<String,String> environment = new HashMap<>();
        // Inject config and TGT
        environment.put("KRB5CCNAME", "/tmp/client_token_cache");
        environment.put("KRB5_CONFIG", "/tmp/krb5.conf");
        // Turn debug on
        environment.put("KRB5_TRACE", "/tmp/diagnostics/krb5_trace.log");
        environment.put("NSPR_LOG_MODULES", "negotiateauth:5");
        environment.put("NSPR_LOG_FILE", "/tmp/diagnostics/firefox.nego.log");
        return environment;
    }

    private String getTrustedUris() {
        // Allow auth negotiation for jenkins under test
        String url = jenkins.url.toExternalForm();
        if (url.endsWith("/")) {
            url = url.substring(0, url.length()-1);
        }
        String trustedUris = url;
        String jenkins_local_hostname = System.getenv("JENKINS_LOCAL_HOSTNAME");
        // if JENKINS_LOCAL_HOSTNAME is set, we add this to FF nego uris
        if (jenkins_local_hostname != null && !jenkins_local_hostname.isEmpty()) {
            try {
                // In the case where JENKINS_LOCAL_HOSTNAME is an IP,
                // we need to add its resolved hostname for auth negotiation
                String hostName = InetAddress.getByName(jenkins_local_hostname).getCanonicalHostName();
                trustedUris = trustedUris + ", " + hostName;
            } catch (UnknownHostException e) {
                e.printStackTrace();
                throw new Error(e);
            }
        }
        return trustedUris;
    }


    private void assertUnauthenticatedRequestIsRejected(CloseableHttpClient httpClient) throws IOException {
        HttpGet get = new HttpGet(jenkins.url.toExternalForm());
        CloseableHttpResponse response = httpClient.execute(get);
        assertEquals("Unauthorized", response.getStatusLine().getReasonPhrase());
        assertEquals("Negotiate", response.getHeaders("WWW-Authenticate")[0].getValue());
    }

    /**
     * HTTP client that does not negotiate.
     */
    // I am not able to get the basic auth to work in FF 45.3.0, so using HttpClient instead
    // org.openqa.selenium.UnsupportedCommandException: Unrecognized command: POST /session/466a800f-eaf8-40cf-a9e8-815f5a6e3c32/alert/credentials
    // alert.setCredentials(new UserAndPassword("user", "ATH"));
    private CloseableHttpClient getBadassHttpClient() {
        return HttpClientBuilder.create().setDefaultAuthSchemeRegistry(
                RegistryBuilder.<AuthSchemeProvider>create()
                    .register(AuthSchemes.BASIC, new BasicSchemeFactory())
                    .build()
        ).build();
    }

    /**
     * Turn the SSO on in Jenkins.
     *
     * @param allowAnonymous Require authentication on all URLs.
     * @param allowBasic Allow basic authentication.
     */
    private void configureSsoUsingPos(KerberosContainer kdc, boolean allowAnonymous, boolean allowBasic) {
        // Turn Jenkins side debugging on
        jenkins.runScript("System.setProperty('sun.security.krb5.debug', 'true');System.setProperty('sun.security.spnego.debug', 'true');");

        GlobalSecurityConfig s = new GlobalSecurityConfig(jenkins);
        s.configure();
        KerberosGlobalConfig kgc = new KerberosGlobalConfig(s);
        kgc.enable();
        kgc.krb5Conf(kdc.getKrb5ConfPath());
        kgc.loginConf(kdc.getLoginConfPath());
        kgc.allowLocalhost(false);
        kgc.allowBasic(allowBasic);
        kgc.allowAnonymous(allowAnonymous);

        s.save();
    }

    private void configureSsoUsingJcasc(KerberosContainer kdc, boolean allowAnonymous, boolean allowBasic) throws IOException {
        JcascManage page = new JcascManage(jenkins);
        Path decl = Files.createTempFile("kerberos-sso", "jcasc");
        decl.toFile().deleteOnExit();
        try (PrintWriter w = new PrintWriter(decl.toFile())) {
            w.println("security:");
            w.println("  kerberosSso:");
            w.println("    enabled: true");
            w.println("    krb5Location: " + kdc.getKrb5ConfPath());
            w.println("    loginLocation: " + kdc.getLoginConfPath());
            w.println("    allowLocalhost: false");
            w.println("    allowBasic: " + allowBasic);
            w.println("    anonymousAccess: " + allowAnonymous);
        }

        page.open();
        page.configure(decl.toAbsolutePath().toString());
    }

    /**
     * Start KDC container populating target dir with generated keytabs and config files.
     */
    private KerberosContainer startKdc() throws IOException {
        KerberosContainer kdc = kerberos.get();
        File target = Files.createTempDirectory(getClass().getSimpleName()).toFile();
        kdc.populateTargetDir(target);
        return kdc;
    }

    /**
     * Create KDC user in backend realm.
     *
     * It is necessary the backend realm recognises all the users kerberos let in. The user is logged in when this method completes.
     */
    private User setupRealmUser() {
        // Populate realm with users
        GlobalSecurityConfig sc = new GlobalSecurityConfig(jenkins);
        sc.configure();
        JenkinsDatabaseSecurityRealm realm = sc.useRealm(JenkinsDatabaseSecurityRealm.class);
        realm.allowUsersToSignUp(true);
        sc.save();
        // The password needs to be the same as in kerberos
        return realm.signup().password("ATH").fullname("Full User Name")
                .email("ath@ath.com")
                .signup("user");
    }

    private class KerberosGlobalConfig extends PageAreaImpl {
        public KerberosGlobalConfig(GlobalSecurityConfig config) {
            super(config, "/com-sonymobile-jenkins-plugins-kerberossso-PluginImpl");
        }

        public KerberosGlobalConfig enable() {
            control("enabled").check();
            control("enabled/advanced-button").click();
            return this;
        }

        public KerberosGlobalConfig krb5Conf(String krb5) {
            control("enabled/krb5Location").set(krb5);
            return this;
        }

        public KerberosGlobalConfig loginConf(String krb5) {
            control("enabled/loginLocation").set(krb5);
            return this;
        }

        public KerberosGlobalConfig allowLocalhost(boolean allow) {
            control("enabled/allowLocalhost").check(allow);
            return this;
        }

        public KerberosGlobalConfig allowBasic(boolean allow) {
            control("enabled/allowBasic").check(allow);
            return this;
        }

        public KerberosGlobalConfig allowAnonymous(boolean login) {
            control("enabled/anonymousAccess").check(login);
            return this;
        }
    }
}
