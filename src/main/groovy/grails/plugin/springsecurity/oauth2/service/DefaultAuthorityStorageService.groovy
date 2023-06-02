package grails.plugin.springsecurity.oauth2.service

import com.github.scribejava.core.model.OAuth2AccessToken
import grails.plugin.springsecurity.SpringSecurityService
import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.oauth2.OAuth2CreateAccountCommand
import grails.plugin.springsecurity.oauth2.SpringSecurityOauth2BaseService
import grails.plugin.springsecurity.oauth2.token.OAuth2SpringToken
import grails.plugin.springsecurity.userdetails.GormUserDetailsService
import grails.plugin.springsecurity.userdetails.GrailsUser
import groovy.transform.CompileDynamic
import groovy.transform.CompileStatic
import groovy.util.logging.Slf4j
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.transaction.TransactionStatus

@CompileStatic
@Slf4j
abstract class DefaultAuthorityStorageService implements AuthorityStorageServiceInterface{

    SpringSecurityOauth2BaseService springSecurityOauth2BaseService
    SpringSecurityService springSecurityService

    @CompileDynamic
    Object createUserRolesAndAuths(OAuth2CreateAccountCommand command, OAuth2SpringToken oAuth2SpringToken, TransactionStatus status){
        def User = springSecurityOauth2BaseService.lookupUserClass()
        def user = User.newInstance()
        user.username = command.username
        user.password = command.password1
        user.enabled = true
        //user.addTooAuthIDs(provider: oAuth2SpringToken.providerName, accessToken: oAuth2SpringToken.socialId, user: user)
        addTooAuthIDs(oAuth2SpringToken.providerName,oAuth2SpringToken.socialId, user )
        if (!validateUser(user) || !saveUser(user)) {
            status.setRollbackOnly()
            return null
        }
        def UserRole = springSecurityOauth2BaseService.lookupUserRoleClass()
        def Role = springSecurityOauth2BaseService.lookupRoleClass()
        def roles = springSecurityOauth2BaseService.roleNames
        for (roleName in roles) {
            log.debug("Creating role " + roleName + " for user " + user.username)
            // Make sure that the role exists.
            UserRole.create user, Role.findOrSaveByAuthority(roleName)
        }
        return user
    }

    @CompileDynamic
    OAuth2SpringToken reAuthenticate(OAuth2SpringToken oAuth2SpringToken, def user){
        // make sure that the new roles are effective immediately
        springSecurityService.reauthenticate(user.username)
        OAuth2SpringToken retVal = springSecurityOauth2BaseService.updateOAuthToken(oAuth2SpringToken, user)
        return retVal
    }

    /**
     * Update the oAuthToken
     * @param oAuthToken
     * @param user
     * @return A current OAuth2SpringToken
     */
    @CompileDynamic
    OAuth2SpringToken updateOAuthToken(OAuth2SpringToken oAuthToken,def user) {
        def conf = SpringSecurityUtils.securityConfig
        String usernamePropertyName = conf.userLookup.usernamePropertyName
        String passwordPropertyName = conf.userLookup.passwordPropertyName
        String enabledPropertyName = conf.userLookup.enabledPropertyName
        String accountExpiredPropertyName = conf.userLookup.accountExpiredPropertyName
        String accountLockedPropertyName = conf.userLookup.accountLockedPropertyName
        String passwordExpiredPropertyName = conf.userLookup.passwordExpiredPropertyName

        String username = user."${usernamePropertyName}"
        String password = user."${passwordPropertyName}"
        boolean enabled = enabledPropertyName ? user."${enabledPropertyName}" : true
        boolean accountExpired = accountExpiredPropertyName ? user."${accountExpiredPropertyName}" : false
        boolean accountLocked = accountLockedPropertyName ? user."${accountLockedPropertyName}" : false
        boolean passwordExpired = passwordExpiredPropertyName ? user."${passwordExpiredPropertyName}" : false

        // authorities

        String authoritiesPropertyName = conf.userLookup.authoritiesPropertyName
        String authorityPropertyName = conf.authority.nameField
        Collection<?> userAuthorities = getAuthorities(user, authoritiesPropertyName);
        def authorities = userAuthorities.collect { new SimpleGrantedAuthority(it."${authorityPropertyName}") }

        oAuthToken.principal = new GrailsUser(username, password, enabled, !accountExpired, !passwordExpired,
                !accountLocked, authorities ?: [GormUserDetailsService.NO_ROLE], user.id)
        oAuthToken.authorities = authorities
        oAuthToken.authenticated = true

        return oAuthToken
    }

    @CompileDynamic
    OAuth2SpringToken createAuthToken(String providerName, OAuth2AccessToken scribeToken) {
        def providerService = springSecurityOauth2BaseService.getProviderService(providerName)
        OAuth2SpringToken oAuthToken = providerService.createSpringAuthToken(scribeToken)
        Class<?> OAuthID = springSecurityOauth2BaseService.lookupOAuthIdClass()
        def oAuthID = findOAuthId(OAuthID, oAuthToken)
        if (oAuthID) {
            updateOAuthToken(oAuthToken, oAuthID.user)
        }
        return oAuthToken
    }


}
