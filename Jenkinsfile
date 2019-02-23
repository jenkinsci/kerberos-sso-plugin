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
        docker.image('jenkins/ath:latest').inside('-v /var/run/docker.sock:/var/run/docker.sock --shm-size 2g') {
            sh """
                eval \$(vnc.sh)
                run.sh firefox latest -Dmaven.test.failure.ignore=true -DforkCount=1 -B -Dtest=KerberosSsoTest
            """
        }
    }
}
