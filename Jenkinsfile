#!/usr/bin/env groovy

/* `buildPlugin` step provided by: https://github.com/jenkins-infra/pipeline-library */
buildPlugin(configurations: [
    [ platform: "windows", jdk: "8", jenkins: "2.150.2" ],
    [ platform: "docker && highmem", jdk: "8", jenkins: "2.150.2" ],
    [ platform: "docker && highmem", jdk: "11", jenkins: "2.150.2" ]
])
