#!/usr/bin/env groovy

/* `buildPlugin` step provided by: https://github.com/jenkins-infra/pipeline-library */
buildPlugin(configurations: [
  [ platform: "linux", jdk: "8", jenkins: null ],
  [ platform: "windows", jdk: "8", jenkins: null ],
  [ platform: "linux", jdk: "8", jenkins: "2.150.2" ], // SECURITY-901
  [ platform: "linux", jdk: "11", jenkins: "2.150.2" ]
])

node('docker && highmem') {
    docker.image('jenkins/ath:acceptance-test-harness-1.63').inside {
        infra.runMaven(["clean", "install", "-Pselenium -Dmaven.test.failure.ignore -B -Dtest=KerberosSsoTest", "8"])
    }
}
