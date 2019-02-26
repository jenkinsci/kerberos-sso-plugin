#!/usr/bin/env groovy

/* `buildPlugin` step provided by: https://github.com/jenkins-infra/pipeline-library */
buildPlugin(configurations: [
  [ platform: "linux", jdk: "8", jenkins: null ],
  [ platform: "windows", jdk: "8", jenkins: null ],
  [ platform: "linux", jdk: "8", jenkins: "2.150.2" ], // SECURITY-901
  [ platform: "linux", jdk: "11", jenkins: "2.150.2" ]
])

stage("UI tests") {
    node('docker && highmem') {
        checkout scm
        // TODO switch to jenkins/ath:acceptance-test-harness-1.65+ after https://issues.jenkins-ci.org/browse/INFRA-2022
        docker.image('jenkins/ath:latest').inside('-v /var/run/docker.sock:/var/run/docker.sock --shm-size 2g') {
            sh """
                mvn clean package -DskipTests # Build .hpi before running ATH so the snapshot is consumed instead of latest released
                eval \$(vnc.sh)
                mvn test -B -Dmaven.test.failure.ignore=true -DforkCount=1 -Ptest-ath
            """
        }
        junit '**/target/surefire-reports/**/*.xml'
    }
}
