[![Build Status](https://ci.jenkins.io/job/Plugins/job/kerberos-sso-plugin/job/master/badge/icon)](https://ci.jenkins.io/job/Plugins/job/kerberos-sso-plugin/job/master/)
[![Contributors](https://img.shields.io/github/contributors/jenkinsci/kerberos-sso-plugin.svg)](https://github.com/jenkinsci/kerberos-sso-plugin/graphs/contributors)
[![Jenkins Plugin](https://img.shields.io/jenkins/plugin/v/kerberos-sso.svg)](https://plugins.jenkins.io/kerberos-sso)
[![GitHub release](https://img.shields.io/github/release/jenkinsci/kerberos-sso-plugin.svg?label=changelog)](https://github.com/jenkinsci/kerberos-sso-plugin/releases/latest)
[![Jenkins Plugin Installs](https://img.shields.io/jenkins/plugin/i/kerberos-sso.svg?color=blue)](https://plugins.jenkins.io/kerberos-sso)

# Kerberos SSO plugin

This plugin achieves Single Sign-On authentication through Kerberos.

## Configuration

Enable Kerberos SSO:

```yaml
  kerberosSso:
    enabled: true
    krb5Location: '/etc/krb5.conf'
    loginLocation: '/etc/login.conf'
    loginServerModule: 'spnego-server'
    loginClientModule: 'spnego-client'
    anonymousAccess: true
    allowLocalhost: false
    allowBasic: true
    allowDelegation: false
    allowUnsecureBasic: false
    promptNtlm: false
```

To disable Kerberos SSO:

```yaml
security:
  kerberosSso:
    enabled: false
```

## Troubleshooting

Enable Jenkins logging with following loggers:

- `com.sonymobile.jenkins.plugins.kerberossso`
- `Spnego` and `SpnegoHttpFilter` (both used by spnego of different versions)
