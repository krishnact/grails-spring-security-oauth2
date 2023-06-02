package grails.plugin.springsecurity.oauth2

import com.github.scribejava.core.model.OAuth2AccessToken
import grails.gorm.transactions.Transactional
import grails.plugin.springsecurity.SpringSecurityService
import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.oauth2.service.AuthorityStorageServiceInterface
import grails.plugin.springsecurity.oauth2.service.DefaultAuthorityStorageService
import grails.plugin.springsecurity.oauth2.token.OAuth2SpringToken
import grails.plugin.springsecurity.userdetails.GormUserDetailsService
import grails.plugin.springsecurity.userdetails.GrailsUser
import groovy.transform.CompileDynamic
import groovy.transform.CompileStatic
import groovy.util.logging.Slf4j
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.transaction.TransactionStatus

import java.util.ArrayList;


@CompileStatic
@Slf4j
class LocalDbAuthStorageService extends DefaultAuthorityStorageService{
    @CompileDynamic
    def findOAuthId(Class<?> OAuthID, OAuth2SpringToken oAuthToken){
        def oAuthID = OAuthID.findByProviderAndAccessToken(oAuthToken.providerName, oAuthToken.socialId)
        return oAuthID;
    }

    @CompileDynamic
    Collection<?> getAuthorities(def user, String authoritiesPropertyName){
        user."${authoritiesPropertyName}"
    }

    @CompileDynamic
    Object findUser(String username, Class<?> User){
        User.findByUsername(username)
    }

    @CompileDynamic
    void addTooAuthIDs(String providerName, String socialId, def user ){
        user.addTooAuthIDs(provider: providerName, accessToken: socialId, user: user)
    }

    @CompileDynamic
    boolean validateUser(def user){
        return user.validate()
    }

    @CompileDynamic
    boolean saveUser(def user){
        return user.save()
    }
    @CompileDynamic
    Object addTooAuthIDs(OAuth2SpringToken oAuth2SpringToken, def currentUser) {
        currentUser.addTooAuthIDs(
                provider: oAuth2SpringToken.providerName,
                accessToken: oAuth2SpringToken.socialId,
                user: currentUser
        )
    }
}
