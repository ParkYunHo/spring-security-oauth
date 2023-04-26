package com.yoonho.authserver.controller

import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

/**
 * @author yoonho
 * @since 2023.04.26
 */
@RestController
class OAuth2AuthorizationController(
    private val oAuth2AuthorizationService: OAuth2AuthorizationService
) {

    @GetMapping("/authorization")
    fun auth(token: String): OAuth2Authorization? {
        return oAuth2AuthorizationService.findByToken(token, OAuth2TokenType.ACCESS_TOKEN)
    }
}