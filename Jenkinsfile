#!/usr/bin/env groovy

/* `buildPlugin` step provided by: https://github.com/jenkins-infra/pipeline-library */
buildPlugin(configurations: [
    [ platform: "windows", jdk: "8", jenkins: null ],
    [ platform: "docker && highmem", jdk: "8", jenkins: null ],
    [ platform: "docker && highmem", jdk: "11", jenkins: "2.164.3" /*Java 11 not supported for any older release*/ ]
])
