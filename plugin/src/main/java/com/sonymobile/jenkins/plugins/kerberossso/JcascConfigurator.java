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

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.util.Secret;
import io.jenkins.plugins.casc.Attribute;
import io.jenkins.plugins.casc.BaseConfigurator;
import io.jenkins.plugins.casc.ConfigurationContext;
import io.jenkins.plugins.casc.ConfiguratorException;
import io.jenkins.plugins.casc.model.CNode;
import io.jenkins.plugins.casc.model.Mapping;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

import javax.annotation.Nonnull;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static io.jenkins.plugins.casc.Attribute.noop;

/*
 * Giving up on JCasC's automagic and using explicit configurator.
 *
 * - JCasC is using setters to configure the object but it does not call @PostConstruct where we could update the servlet filter once it is done.
 * - @DataBoundConstructor approach does not work as the GlobalConfiguration is a singleton created by Jenkins that is being updated so the JCasC created instance is never replaced in Extension list.
 */
@Restricted(NoExternalUse.class)
@Extension
public class JcascConfigurator extends BaseConfigurator<PluginImpl> {

    public JcascConfigurator() {
        super();
    }

    @Override
    protected PluginImpl instance(Mapping mapping, ConfigurationContext context) {
        return PluginImpl.getInstance();
    }

    @Override
    protected void configure(Mapping m, PluginImpl i, boolean dryrun, ConfigurationContext context) throws ConfiguratorException {
        boolean enabled = read(m, "enabled", false);
        i.setEnabled(enabled);
        if (enabled) {
            i.setAccountName(read(m, "accountName", PluginImpl.DEFAULT_SERVICE_ACCOUNT));
            i.setPassword(Secret.fromString(read(m, "password", null)));

            String redirect = read(m, "redirect", null);
            i.setRedirectEnabled(redirect != null);
            if (redirect != null) {
                i.setRedirect(redirect);
            }

            i.setKrb5Location(read(m, "krb5Location", PluginImpl.DEFAULT_KRB5_CONF));
            i.setLoginLocation(read(m, "loginLocation", PluginImpl.DEFAULT_LOGIN_CONF));
            i.setLoginServerModule(read(m, "loginServerModule", PluginImpl.DEFAULT_SPNEGO_SERVER));
            i.setLoginClientModule(read(m, "loginClientModule", PluginImpl.DEFAULT_SPNEGO_CLIENT));
            i.setAnonymousAccess(read(m, "anonymousAccess", PluginImpl.DEFAULT_ANONYMOUS_ACCESS));
            i.setAllowLocalhost(read(m, "allowLocalhost", PluginImpl.DEFAULT_ALLOW_LOCALHOST));
            i.setAllowBasic(read(m, "allowBasic", PluginImpl.DEFAULT_ALLOW_BASIC));
            i.setAllowDelegation(read(m, "allowDelegation", PluginImpl.DEFAULT_ALLOW_DELEGATION));
            i.setAllowUnsecureBasic(read(m, "allowUnsecureBasic", PluginImpl.DEFAULT_ALLOW_UNSECURE_BASIC));
            i.setPromptNtlm(read(m, "promptNtlm", PluginImpl.DEFAULT_PROMPT_NTLM));
        }
        i.removeFilter();
        i.registerFilter();
    }

    private String read(Mapping m, String key, String def) throws ConfiguratorException {
        CNode field = m.remove(key);
        if (field == null) {
            return def;
        }
        return field.asScalar().getValue();
    }

    private boolean read(Mapping m, String key, boolean def) throws ConfiguratorException {
        CNode field = m.remove(key);
        if (field == null) {
            return def;
        }
        return Boolean.parseBoolean(field.asScalar().getValue());
    }

    @Override
    public Class<PluginImpl> getTarget() {
        return PluginImpl.class;
    }

    @Override
    public @Nonnull Set<Attribute<PluginImpl, ?>> describe() {
        return new HashSet<>(Arrays.asList(
                new Attribute<PluginImpl, Boolean>("enabled", String.class).getter(PluginImpl::getEnabled).setter(noop()),
                new Attribute<PluginImpl, String>("accountName", String.class).getter(PluginImpl::getAccountName).setter(noop()),
                new Attribute<PluginImpl, Secret>("password", String.class).getter(PluginImpl::getPassword).setter(noop()),
                new Attribute<PluginImpl, String>("redirect", String.class).getter(PluginImpl::getRedirect).setter(noop()),
                new Attribute<PluginImpl, String>("krb5Location", String.class).getter(PluginImpl::getKrb5Location).setter(noop()),
                new Attribute<PluginImpl, String>("loginLocation", String.class).getter(PluginImpl::getLoginLocation).setter(noop()),
                new Attribute<PluginImpl, String>("loginServerModule", String.class).getter(PluginImpl::getLoginServerModule).setter(noop()),
                new Attribute<PluginImpl, String>("loginClientModule", String.class).getter(PluginImpl::getLoginClientModule).setter(noop()),
                new Attribute<PluginImpl, Boolean>("anonymousAccess", String.class).getter(PluginImpl::getAnonymousAccess).setter(noop()),
                new Attribute<PluginImpl, Boolean>("allowLocalhost", String.class).getter(PluginImpl::isAllowLocalhost).setter(noop()),
                new Attribute<PluginImpl, Boolean>("allowBasic", String.class).getter(PluginImpl::isAllowBasic).setter(noop()),
                new Attribute<PluginImpl, Boolean>("allowDelegation", String.class).getter(PluginImpl::isAllowDelegation).setter(noop()),
                new Attribute<PluginImpl, Boolean>("allowUnsecureBasic", String.class).getter(PluginImpl::isAllowUnsecureBasic).setter(noop()),
                new Attribute<PluginImpl, Boolean>("promptNtlm", String.class).getter(PluginImpl::isPromptNtlm).setter(noop())
        ));
    }

    @Override
    public CNode describe(PluginImpl instance, ConfigurationContext context) throws Exception {
        Mapping mapping = new Mapping();
        for (Attribute<PluginImpl, ?> attribute : getAttributes()) {
            CNode value = attribute.describe(instance, context);
            if (value != null) {
                mapping.put(attribute.getName(), value);
            }
        }
        return mapping;
    }

    @Override
    public @Nonnull String getName() {
        return PluginImpl.JCASC_NAME;
    }
}
