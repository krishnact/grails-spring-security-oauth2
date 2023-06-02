package grails.plugin.springsecurity.oauth2

import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.oauth2.exception.OAuth2Exception
import grails.util.Holders

class SpringSecurityOauth2UrlMappings {

    static mappings = {
        def active = Holders.grailsApplication.config.grails?.plugin?.springsecurity?.oauth2?.active
        def controllerName = Holders.grailsApplication.config.grails?.plugin?.springsecurity?.oauth2?.controllerName
        if (controllerName == null){
            controllerName = 'springSecurityOAuth2' //'grailsSocialOAuth2'
        }
        def enabled = (active instanceof Boolean) ? active : true
        if (enabled && SpringSecurityUtils.securityConfig?.active) {
            "/oauth2/$provider/authenticate"(controller: controllerName, action: 'authenticate')
            "/oauth2/$provider/callback"(controller: controllerName, action: 'callback')
            "/oauth2/$provider/success"(controller: controllerName, action: 'onSuccess')
            "/oauth2/$provider/failure"(controller: controllerName, action: 'onFailure')
            "/oauth2/ask"(controller: controllerName, action: 'ask')
            "/oauth2/linkaccount"(controller: controllerName, action: 'linkAccount')
            "/oauth2/createaccount"(controller: controllerName, action: 'createAccount')
            '500'(controller: 'login', action: 'auth', exception: OAuth2Exception)
        }else{
            println "Not Oauth2 pluging active so not adding URL mappings"
        }
    }
}
