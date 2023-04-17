package com.yoonho.client.controller

import org.slf4j.LoggerFactory
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import java.time.Instant

/**
 * @author yoonho
 * @since 2023.04.09
 */
@RestController
class IndexController(
    private val clientRegistrationRepository: ClientRegistrationRepository
) {
    private val log = LoggerFactory.getLogger(this::class.java)

    @GetMapping("/")
    fun index(): String {
        val repo: ClientRegistration = clientRegistrationRepository.findByRegistrationId("keycloak")

        log.info(" >>> ClientRegistrationRepository - clientId: ${repo.clientId}, redirect_uri: ${repo.redirectUri}")

        return "index"
    }

    @GetMapping("/user")
    fun user(accessToken: String): OAuth2User {
        val clientRegistration: ClientRegistration = clientRegistrationRepository.findByRegistrationId("keycloak")
        val oAuth2AccessToken: OAuth2AccessToken = OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            accessToken,
            Instant.now(),
            Instant.MAX
        )

        val oAuth2UserRequest: OAuth2UserRequest = OAuth2UserRequest(clientRegistration, oAuth2AccessToken)
        val defaultOAuth2UserService: DefaultOAuth2UserService = DefaultOAuth2UserService()
        val oAuth2User:OAuth2User = defaultOAuth2UserService.loadUser(oAuth2UserRequest)

        return oAuth2User
    }

    @GetMapping("/oidc")
    fun oidc(accessToken: String, idToken: String): OAuth2User {
        val clientRegistration: ClientRegistration = clientRegistrationRepository.findByRegistrationId("keycloak")
        // Access Token
        val oAuth2AccessToken: OAuth2AccessToken = OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            accessToken,
            Instant.now(),
            Instant.MAX
        )

        // ID Token
        val idTokenClaims = mapOf(
            IdTokenClaimNames.ISS to "http://localhost:8081/realms/oauth2",
            IdTokenClaimNames.SUB to "OIDC0",
            "preferred_username" to "user"
        )
        val oidcToken: OidcIdToken = OidcIdToken(
            idToken,
            Instant.now(),
            Instant.MAX,
            idTokenClaims
        )

        val oidcUserRequest: OidcUserRequest = OidcUserRequest(clientRegistration, oAuth2AccessToken, oidcToken)
        val oidcUserService: OidcUserService = OidcUserService()
        val oAuth2User:OAuth2User = oidcUserService.loadUser(oidcUserRequest)

        return oAuth2User
    }

}