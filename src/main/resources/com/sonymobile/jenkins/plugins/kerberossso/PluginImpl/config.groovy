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

import com.sonymobile.jenkins.plugins.kerberossso.PluginImpl
import lib.FormTagLib

def form = namespace(FormTagLib)
def location = "/plugin/kerberos-sso/"

PluginImpl p = (PluginImpl) instance

form.section(title:"Kerberos Single Sign-On") {
    form.optionalBlock(title:_("EnablePlugin"), field:"enabled", checked:p.enabled) {

        form.optionalBlock(title:_("RedirectCheck"), field:"redirectEnabled", checked:p.redirectEnabled) {
            form.entry(field:"redirect", title:_("RedirectTo")) {
                form.textbox(value:p.redirect)
            }
        }

        form.advanced(title: _("Kerberos properties"), align:"left") {

            form.entry(field:"account", title:_("Service Account")) {
                form.textbox(value:p.accountName)
            }

            form.entry(field:"password", title:_("Password")) {
                form.password(value:p.password)
            }

            form.entry(field: "krb5Location", title:_("Location of krb5.conf")) {
                form.textbox(value:p.krb5Location)
            }

            form.entry(field: "loginLocation", title:_("Location of login.conf")) {
                form.textbox(value:p.loginLocation)
            }

            form.entry(field: "loginServerModule", title:_("Login Server Module")) {
                form.textbox(value:p.loginServerModule)
            }

            form.entry(field: "loginClientModule", title:_("Login Client Module")) {
                form.textbox(value:p.loginClientModule)
            }

            form.entry(title:_("Allow anonymous access")) {
                form.checkbox(field: "anonymousAccess", checked:p.anonymousAccess)
            }

            form.entry(title:_("Allow Localhost")) {
                form.checkbox(field: "allowLocalhost", checked:p.allowLocalhost)
            }

            form.entry(title:_("Allow Basic")) {
                form.checkbox(field: "allowBasic", checked:p.allowBasic)
            }

            form.entry(title:_("Allow Delegation")) {
                form.checkbox(field: "allowDelegation", checked:p.allowDelegation)
            }

            form.entry(title:_("Allow Unsecure Basic")) {
                form.checkbox(field: "allowUnsecureBasic", checked:p.allowUnsecureBasic)
            }

            form.entry(title:_("Prompt NTLM")) {
                form.checkbox(field: "promptNtlm", checked:p.promptNtlm)
            }
        }
    }
}



