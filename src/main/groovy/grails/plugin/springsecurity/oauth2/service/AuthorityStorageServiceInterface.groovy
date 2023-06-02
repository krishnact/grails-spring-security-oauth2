package grails.plugin.springsecurity.oauth2.service

import com.github.scribejava.core.model.OAuth2AccessToken
import grails.plugin.springsecurity.oauth2.OAuth2CreateAccountCommand
import grails.plugin.springsecurity.oauth2.token.OAuth2SpringToken
import org.springframework.transaction.TransactionStatus

interface AuthorityStorageServiceInterface {

    def addTooAuthIDs(OAuth2SpringToken oAuth2SpringToken, def currentUser);

    def findUser(String username, Class<?> User)
//    String lookupOAuthIdClassName()
//    Class<?> lookupOAuthIdClass()
//    String lookupUserClassName()
//    Class<?> lookupUserClass()
//    String lookupUserRoleClassName()
//    Class<?> lookupUserRoleClass()
//    String lookupRoleClassName()
//    Class<?> lookupRoleClass()
//    ArrayList<String> getRoleNames()
    Object createUserRolesAndAuths(OAuth2CreateAccountCommand command, OAuth2SpringToken oAuth2SpringToken, TransactionStatus status);
    OAuth2SpringToken reAuthenticate(OAuth2SpringToken oAuth2SpringToken, def user)
    OAuth2SpringToken createAuthToken(String providerName, OAuth2AccessToken scribeToken)
}