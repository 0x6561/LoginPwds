#!/bin/bash
javapackager -deploy -native -outdir packages -outfile LoginPwds -v \
    -srcdir dist -srcfiles net.ea.loginpwds.jar -appclass net.ea.loginpwds.LoginPwdFrame \
       -name "LoginPwds" -title "LoginPwds"
