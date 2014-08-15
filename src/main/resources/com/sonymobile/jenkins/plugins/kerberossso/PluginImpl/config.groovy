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

package com.sonymobile.jenkins.plugins.kerberossso.PluginImpl

import lib.FormTagLib

def form = namespace(FormTagLib)
def location = "/plugin/kerberos-sso/"

form.section(title:"Kerberos Single Sign-On") {
    form.optionalBlock(title:_("EnablePlugin"), help:location+"/help-overview.html", field:"enabled", checked:my.enabled) {

        form.optionalBlock(title:_("RedirectCheck"), help:location+"/help-redirect.html", field:"redirectEnabled", checked:my.redirectEnabled) {
            form.entry(field:"redirect", title:_("RedirectTo")) {
                form.textbox(value:my.redirect)
            }
        }

        form.section(title:_("Kerberos properties")) {
            if (my.restartNeeded) {
                form.entry () {
                    p(style:"color:red;font-weight:bold", _("RestartNotice"))
                }
            }

            form.entry(field:"account", title:_("Service Account"), help:location+"/help-service-account.html") {
                form.textbox(value:my.accountName)
            }

            form.entry(field:"password", title:_("Password")) {
                form.password(value:my.password)
            }

            form.entry(field: "krb5Location", title:_("Location of krb5.conf"), help:location+"/help-krb5-location.html") {
                form.textbox(value:my.krb5Location)
            }

            form.entry(field: "loginLocation", title:_("Location of login.conf"), help:location+"/help-login-location.html") {
                form.textbox(value:my.loginLocation)
            }

            form.entry(field: "loginServerModule", title:_("Login Server Module"), help:location+"/help-server-module.html") {
                form.textbox(value:my.loginServerModule)
            }

            form.entry(field: "loginClientModule", title:_("Login Client Module"), help:location+"/help-client-module.html") {
                form.textbox(value:my.loginClientModule)
            }

            form.entry(title:_("Allow Localhost"), help:location+"/help-allow-localhost.html") {
                form.checkbox(field: "allowLocalhost", checked:my.allowLocalhost)
            }

            form.entry(title:_("Allow Basic"), help:location+"/help-allow-basic.html") {
                form.checkbox(field: "allowBasic", checked:my.allowBasic)
            }

            form.entry(title:_("Allow Delegation"), help:location+"/help-allow-delegation.html") {
                form.checkbox(field: "allowDelegation", checked:my.allowDelegation)
            }

            form.entry(title:_("Allow Unsecure Basic"), help:location+"/help-allow-unsecure-basic.html") {
                form.checkbox(field: "allowUnsecureBasic", checked:my.allowUnsecureBasic)
            }

            form.entry(title:_("Prompt NTLM"), help:location+"/help-prompt-ntlm.html") {
                form.checkbox(field: "promptNtlm", checked:my.promptNtlm)
            }
        }
    }
}



