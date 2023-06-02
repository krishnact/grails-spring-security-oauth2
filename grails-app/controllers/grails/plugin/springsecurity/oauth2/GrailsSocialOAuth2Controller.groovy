package grails.plugin.springsecurity.oauth2


import com.github.scribejava.core.model.OAuth2AccessToken
import com.sun.istack.internal.Nullable
import grails.compiler.GrailsCompileStatic
import grails.plugin.springsecurity.SpringSecurityService
import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.annotation.Secured
import grails.plugin.springsecurity.oauth2.exception.OAuth2Exception
import grails.plugin.springsecurity.oauth2.service.AuthorityStorageServiceInterface
import grails.plugin.springsecurity.oauth2.token.OAuth2SpringToken
import grails.plugin.springsecurity.userdetails.GrailsUser
import groovy.transform.CompileDynamic
import groovy.transform.CompileStatic
import groovy.util.logging.Slf4j
import org.apache.commons.lang.StringUtils
import org.apache.commons.lang.exception.ExceptionUtils
import org.apache.commons.validator.routines.UrlValidator
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.transaction.TransactionStatus
import org.springframework.web.servlet.ModelAndView

/**
 * Controller for handling OAuth authentication request and
 * integrating it into SpringSecurity
 *
 * Based on SpringSecurityOAuthController:2.1.0.RC4
 */
//@CompileStatic
@Slf4j
@Secured('permitAll')
//@GrailsCompileStatic
class GrailsSocialOAuth2Controller {

    @Value('${grails.plugin.springsecurity.oauth2.controllerName}')
    String controllerName

    @Value('${grails.plugin.springsecurity.oauth2.useTransaction}')
    boolean useTransaction


    public static final String SPRING_SECURITY_OAUTH_TOKEN = 'springSecurityOAuthToken'

    SpringSecurityOauth2BaseService springSecurityOauth2BaseService
    SpringSecurityService springSecurityService
    @Autowired
    AuthorityStorageServiceInterface authStorageService
    /**
     * Authenticate
     */
    @CompileDynamic
    def authenticate() {
        String providerName = params.provider
        if (StringUtils.isBlank(providerName)) {
            throw new OAuth2Exception("No provider defined")
        }
        log.debug "authenticate ${providerName}"
        String url = springSecurityOauth2BaseService.getAuthorizationUrl(providerName)
        log.debug "redirect url from s2oauthservice=${url}"
        if (!UrlValidator.instance.isValid(url)) {
            flash.message = "Authorization url for provider '${providerName}' is invalid."
            redirect(controller: 'login', action: 'index')
        }
        redirect(url: url)
    }

    /**
     * Default callback function for first OAuth2 Step
     */
    @CompileDynamic
    def callback() {
        String providerName = params.provider
        log.debug("Callback for " + providerName)

        // Check if we got an AuthCode from the server query
        String authCode = params.code
        log.debug("AuthCode: " + authCode)
        if (!authCode || authCode.isEmpty()) {
            throw new OAuth2Exception("No AuthCode in callback for provider '${providerName}'")
        }

        def providerService = springSecurityOauth2BaseService.getProviderService(providerName)
        OAuth2AccessToken accessToken
        try {
            accessToken = providerService.getAccessToken(authCode)
        } catch (Exception exception) {
            log.error("Could not authenticate with oAuth2. " + ExceptionUtils.getMessage(exception), exception)
            log.debug(ExceptionUtils.getStackTrace(exception))
            redirect(uri: springSecurityOauth2BaseService.getFailureUrl(providerName))
            return
        }
        session[springSecurityOauth2BaseService.sessionKeyForAccessToken(providerName)] = accessToken
        redirect(uri: springSecurityOauth2BaseService.getSuccessUrl(providerName))
    }

    @CompileDynamic
    def onFailure(String provider) {
        flash.error = "Error authenticating with ${provider}"
        log.warn("Error authentication with OAuth2Provider ${provider}")
        authenticateAndRedirect(null, getDefaultTargetUrl())
    }

    def onSuccess(String provider) {
        if (!provider) {
            log.warn "The Spring Security OAuth callback URL must include the 'provider' URL parameter"
            throw new OAuth2Exception("The Spring Security OAuth callback URL must include the 'provider' URL parameter")
        }
        def sessionKey = springSecurityOauth2BaseService.sessionKeyForAccessToken(provider)
        if (!session[sessionKey]) {
            log.warn "No OAuth token in the session for provider '${provider}'"
            throw new OAuth2Exception("Authentication error for provider '${provider}'")
        }
        // Create the relevant authentication token and attempt to log in.
        OAuth2SpringToken oAuthToken = authStorageService.createAuthToken(provider, (OAuth2AccessToken) (session[sessionKey]))

        if (oAuthToken.principal instanceof GrailsUser) {
            authenticateAndRedirect(oAuthToken, getDefaultTargetUrl())
        } else {
            // This OAuth account hasn't been registered against an internal
            // account yet. Give the oAuthID the opportunity to create a new
            // internal account or link to an existing one.
            session[SPRING_SECURITY_OAUTH_TOKEN] = oAuthToken

            def redirectUrl = springSecurityOauth2BaseService.getAskToLinkOrCreateAccountUri()
            if (!redirectUrl) {
                log.warn "grails.plugin.springsecurity.oauth.registration.askToLinkOrCreateAccountUri configuration option must be set"
                throw new OAuth2Exception('Internal error')
            }
            log.debug "Redirecting to askToLinkOrCreateAccountUri: ${redirectUrl}"
            redirect(redirectUrl instanceof Map ? redirectUrl : [uri: redirectUrl])
        }
    }

    def ask() {
        if (springSecurityService.isLoggedIn()) {
            def currentUser = springSecurityService.currentUser
            OAuth2SpringToken oAuth2SpringToken = session[SPRING_SECURITY_OAUTH_TOKEN] as OAuth2SpringToken
            // Check for token in session
            if (!oAuth2SpringToken) {
                log.warn("ask: OAuthToken not found in session")
                throw new OAuth2Exception('Authentication error')
            }
            // Try to add the token to the OAuthID's
            authStorageService.addTooAuthIDs(
                    oAuth2SpringToken,
                    currentUser
            )

            if (authStorageService.isUserValid(currentUser)) {
                // Could assign the token to the OAuthIDs. Login and redirect
                oAuth2SpringToken = springSecurityOauth2BaseService.updateOAuthToken(oAuth2SpringToken, currentUser)
                authenticateAndRedirect(oAuth2SpringToken, getDefaultTargetUrl())
                return
            }
        }
        // There seems to be a new one in the town aka 'There is no one logged in'
        // Ask to create a new account or link an existing user to it
        // We will use same view that is used by original plugin. We want switching between the plugins to be as easy as
        // possible.
        return new ModelAndView("/springSecurityOAuth2/ask", [:])
    }

    /**
     * Associates an OAuthID with an existing account. Needs the user's password to ensure
     * that the user owns that account, and authenticates to verify before linking.
     */
    @CompileDynamic
    def linkAccount(OAuth2LinkAccountCommand command) {
        OAuth2SpringToken oAuth2SpringToken = session[SPRING_SECURITY_OAUTH_TOKEN] as OAuth2SpringToken
        if (!oAuth2SpringToken) {
            log.warn "linkAccount: OAuthToken not found in session"
            throw new OAuth2Exception('Authentication error')
        }
        if (request.post) {
            if (!springSecurityOauth2BaseService.authenticationIsValid(command.username, command.password)) {
                log.info "Authentication error for use ${command.username}"
                command.errors.rejectValue("username", "OAuthLinkAccountCommand.authentication.error")
                render view: 'ask', model: [linkAccountCommand: command]
                return
            }
            def commandValid = command.validate()
            def User = springSecurityOauth2BaseService.lookupUserClass()
            Closure cc = { TransactionStatus status ->
                //def User = springSecurityOauth2BaseService.lookupUserClass()
                def user = authStorageService.findUser(command.username, User) //User.findByUsername(command.username)
                if (user) {
                    //user.addTooAuthIDs(provider: oAuth2SpringToken.providerName, accessToken: oAuth2SpringToken.socialId, user: user)
                    authStorageService.addTooAuthIDs(oAuth2SpringToken,user)
                    if (authStorageService.isUserValid(user)) {
                        oAuth2SpringToken = springSecurityOauth2BaseService.updateOAuthToken(oAuth2SpringToken, user)
                        return true
                    } else {
                        return false
                    }
                } else {
                    command.errors.rejectValue("username", "OAuthLinkAccountCommand.username.not.exists")
                }
                status.setRollbackOnly()
                return false
            }
            boolean linked = commandValid
            if (linked){
                if (useTransaction){
                    linked = (User.withTransaction cc)
                }else{
                    linked = cc.call(null)
                }
            }
            if (linked) {
                authenticateAndRedirect(oAuth2SpringToken, getDefaultTargetUrl())
                return
            }
        }
        render view: 'ask', model: [linkAccountCommand: command]
    }

    /**
     * Create ne account and associate it with the oAuthID
     */
    @CompileDynamic
    def createAccount(OAuth2CreateAccountCommand command) {
        OAuth2SpringToken oAuth2SpringToken = session[SPRING_SECURITY_OAUTH_TOKEN] as OAuth2SpringToken
        if (!oAuth2SpringToken) {
            log.warn "createAccount: OAuthToken not found in session"
            throw new OAuth2Exception('Authentication error')
        }
        if (request.post) {
            if (!springSecurityService.loggedIn) {
                def commandValid = command.validate()
                def User = springSecurityOauth2BaseService.lookupUserClass()
                Closure cc = {TransactionStatus status ->
                    def user = authStorageService.createUserRolesAndAuths(command, oAuth2SpringToken, status)
                    if (user != null){
                        return true
                    }
                    return false;
                }

                boolean created = commandValid;
                if (created){
                    if (useTransaction){
                        created = (User.withTransaction cc)
                    }else{
                        created = cc.call(null)
                    }
                }
                if (created) {
                    oAuth2SpringToken = authStorageService.reAuthenticate()
                    authenticateAndRedirect(oAuth2SpringToken, getDefaultTargetUrl())
                    return
                }
            }
        }
        render view: 'ask', model: [createAccountCommand: command]
    }

    /**
     * Set authentication token and redirect to the page we came from
     * @param oAuthToken
     * @param redirectUrl
     */
    protected void authenticateAndRedirect(@Nullable OAuth2SpringToken oAuthToken, redirectUrl) {
        session.removeAttribute SPRING_SECURITY_OAUTH_TOKEN
        SecurityContextHolder.context.authentication = oAuthToken
        redirect(redirectUrl instanceof Map ? redirectUrl : [uri: redirectUrl])
    }

    /**
     * Get default Url
     * @return
     */
    @CompileDynamic
    protected Map getDefaultTargetUrl() {
        def config = SpringSecurityUtils.securityConfig
        def savedRequest = SpringSecurityUtils.getSavedRequest(session)
        def defaultUrlOnNull = '/'
        if (savedRequest && !config.successHandler.alwaysUseDefault) {
            return [url: (savedRequest.redirectUrl ?: defaultUrlOnNull)]
        }
        return [uri: (config.successHandler.defaultTargetUrl ?: defaultUrlOnNull)]
    }
}