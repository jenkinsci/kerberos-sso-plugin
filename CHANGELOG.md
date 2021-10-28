#### **Version 1.5 (released 2019-02-14)**

-   Fixed redirect when Jenkins has a context path

-   [Fixed issues with the User Seed after
    SECURITY-901](https://github.com/jenkinsci/kerberos-sso-plugin/commit/0e35355a0436e55c5e96afbf0dea7bb7563576fb)
    -   Note this version or newer is needed to work correctly with
        Jenkins newer than 2.260 or 2.150.2 respectively.

#### **Version 1.4 (released 2017-08-11)**

-   Skip authentication for unprotected root actions

#### **Version 1.3 (released 2016-10-07)**

-   Redirect to previous page after explicit login in anonymous mode.

#### **Version 1.2 (released 2016-10-05)**

-   spnego.sourceforge.net replaced with active fork:
    <https://github.com/codelibs/spnego>
-   Anonymous mode.

#### **Version 1.0.2 (released March 23 2015)**

-   Exception in automatic login for accessing userContent.

#### **Version 1.0.1 (released November 05 2014)**

-   Bugfix when calling fireLoggedIn after a user logs in.

#### **Version 1.0.0 (released Aug 15 2014)**

-   First release