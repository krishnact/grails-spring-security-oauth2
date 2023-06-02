/* Copyright 2006-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package grails.plugin.springsecurity.oauth2

import com.github.scribejava.core.model.OAuth2AccessToken
import grails.plugin.springsecurity.SpringSecurityService
import org.grails.taglib.GrailsTagException
import org.springframework.beans.factory.annotation.Value

class OAuth2TagLib {
    @Value('${grails.plugin.springsecurity.oauth2.controllerName}')
    String controllerName
    static namespace = "oauth2"

    SpringSecurityOauth2BaseService springSecurityOauth2BaseService
    SpringSecurityService springSecurityService

    /**
     * Creates a link to connect to the given provider.
     */
    def connect = { attrs, body ->
        String provider = attrs.provider
        if (!provider) {
            throw new GrailsTagException('No provider specified for <oauth2:connect /> tag. Try <oauth2:connect provider="your-provider-name" />')
        }
        Map a = attrs + [url: [controller: controllerName, action: 'authenticate', params: [provider: provider]]]
        out << g.link(a, body)
    }

    /**
     * Renders the body if the user is authenticated with the given provider.
     */
    def ifLoggedInWith = { attrs, body ->
        String provider = attrs.provider
        if (currentUserIsLoggedInWithProvider(provider)) {
            out << body()
        }
    }

    /**
     * Renders the body if the user is not authenticated with the given provider.
     */
    def ifNotLoggedInWith = { attrs, body ->
        String provider = attrs.provider
        if (!currentUserIsLoggedInWithProvider(provider)) {
            out << body()
        }
    }

    private boolean currentUserIsLoggedInWithProvider(String provider) {
        if (!provider || !springSecurityService.isLoggedIn()) {
            return false
        }
        def sessionKey = springSecurityOauth2BaseService.sessionKeyForAccessToken(provider)
        return (session[sessionKey] && session[sessionKey] instanceof OAuth2AccessToken)
    }
}
