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

package com.sonymobile.jenkins.plugins.kerberos_sso.PluginImpl

import lib.FormTagLib

def form = namespace(FormTagLib)
def location = "/plugin/kerberos-sso/"


//TODO: It might work better in the blocks to use my.enabled etc.
def oldEnabled = it.enabled

def oldAccountName = it.accountName
def oldPassword = it.password

def oldRedirectEnabled = it.redirectEnabled
def oldRedirect = it.redirect

def oldKrb5Location = it.krb5Location
def oldLoginLocation = it.loginLocation
def oldLoginServerModule = it.loginServerModule
def oldLoginClientModule = it.loginClientModule
def oldAllowLocalhost = it.allowLocalhost
def oldAllowBasic = it.allowBasic
def oldAllowDelegation = it.allowDelegation
def oldAllowUnsecureBasic = it.allowUnsecureBasic
def oldPromptNtlm = it.promptNtlm

def restartNeeded = it.restartNeeded

// TODO: Investigate if it's possible to data-bind with field only. This require PluginImpl to use descriptorImpl
form.section(title:"Kerberos Single Sign-On") {
    form.optionalBlock(title:"Enable Single Sign-On plugin", help:location+"/help-overview.html", field:"enabled", checked:oldEnabled) {

        form.optionalBlock(title:"Redirect if domain is not present in URL", help:location+"/help-redirect.html", field:"redirectEnabled", checked:oldRedirectEnabled) {
            form.entry(field:"redirect", title:"Domain to redirect to") {
                form.textbox(value: oldRedirect)
            }
        }

        form.section(title:"Kerberos properties") {
            if (restartNeeded) {
                form.entry () {
                    p(style:"color:red;font-weight:bold", "Any changes made in this section will take place after " +
                            "Jenkins has been restarted")
                }
            }

            form.entry(field:"account", title:"Service Account", help:location+"/help-service-account.html") {
                form.textbox(value:oldAccountName)
            }

            form.entry(field:"password", title:"Password") {
                form.password(value:oldPassword)
            }

            form.entry(field: "krb5Location", title: "Location of krb5.conf", help:location+"/help-krb5-location.html") {
                form.textbox(value:oldKrb5Location)
            }

            form.entry(field: "loginLocation", title: "Location of login.conf", help:location+"/help-login-location.html") {
                form.textbox(value:oldLoginLocation)
            }

            form.entry(field: "loginServerModule", title: "Login Server Module", help:location+"/help-server-module.html") {
                form.textbox(value:oldLoginServerModule)
            }

            form.entry(field: "loginClientModule", title: "Login Client Module", help:location+"/help-client-module.html") {
                form.textbox(value:oldLoginClientModule)
            }

            form.entry(title:"Allow Localhost", help:location+"/help-allow-localhost.html") {
                form.checkbox(field: "allowLocalhost", checked:oldAllowLocalhost)
            }

            form.entry(title:"Allow Basic", help:location+"/help-allow-basic.html") {
                form.checkbox(field: "allowBasic", checked:oldAllowBasic)
            }

            form.entry(title:"Allow Delegation", help:location+"/help-allow-delegation.html") {
                form.checkbox(field: "allowDelegation", checked:oldAllowDelegation)
            }

            form.entry(title:"Allow Unsecure Basic", help:location+"/help-allow-unsecure-basic.html") {
                form.checkbox(field: "allowUnsecureBasic", checked:oldAllowUnsecureBasic)
            }

            form.entry(title:"Prompt NTLM", help:location+"/help-prompt-ntlm.html") {
                form.checkbox(field: "promptNtlm", checked:oldPromptNtlm)
            }

        }

    }

}



