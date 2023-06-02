

Spring Security OAuth2 Plugin
=======
[![Java CI](https://github.com/grails/grails-spring-security-oauth2/actions/workflows/gradle.yml/badge.svg)](https://github.com/grails/grails-spring-security-oauth2/actions/workflows/gradle.yml)

This is a fork of (https://github.com/grails/grails-spring-security-oauth2.git) 2.0.x branch at version 2.0.0-RC1. 

https://github.com/grails/grails-spring-security-oauth2/commit/e614f94a76d908498d22b73a4ba3281b01516cdb

It is different from the original plugin in following way:

It separates Oauth storage from controller. Current plugin assumes that storage is always going to be in some database. This version of plugin implements a service to do that but also provides a way to implement your own storage provider.
 

See the [official plugin README](https://github.com/grails/grails-spring-security-oauth2.git) for documentation.

How to build?

gradlew -DskipTests build publishToMavenLocal

Use to include in project?
```groovy
implementation 'org.himalay.grails.plugins:spring-security-oauth2:2.0.0-SNAPSHOT'
```

Then make sure that you exclude original plugin from provider specific plugins as shown below for Google plugin:
```groovy
implementation ("grails.spring.security.oauth2:spring-security-oauth2-google:1.5.1.BUILD-SNAPSHOT"){
        exclude group: 'org.grails.plugins', module: 'spring-security-oauth2'
    }
```

Example:

For an example of how to use this plugin please check this project: https://github.com/krishnact/grails-social , tag v1.0

