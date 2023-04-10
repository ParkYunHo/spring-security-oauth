package com.yoonho.client.controller

import org.slf4j.LoggerFactory
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

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



}