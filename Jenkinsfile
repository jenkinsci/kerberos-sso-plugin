#!/usr/bin/env groovy

/* `buildPlugin` step provided by: https://github.com/jenkins-infra/pipeline-library */
buildPlugin(configurations: [
    [ platform: "windows", jdk: "8", jenkins: "2.150.2 -pl='!com.sonymobile.jenkins.plugins.kerberos-sso:ui-tests'" ],
    [ platform: "linux", jdk: "8", jenkins: "2.150.2" ],
    [ platform: "linux", jdk: "11", jenkins: "2.150.2 -pl='!com.sonymobile.jenkins.plugins.kerberos-sso:ui-tests'" ]
])

//stage("UI tests") {
//    node('docker && highmem') {
//        checkout scm
//        docker.image('jenkins/ath:acceptance-test-harness-1.67').inside('-v /var/run/docker.sock:/var/run/docker.sock --shm-size 2g') {
//            sh """
//                eval \$(vnc.sh)
//                mvn clean package
//            """
//        }
//        junit '**/target/surefire-reports/**/*.xml'
//    }
//}
