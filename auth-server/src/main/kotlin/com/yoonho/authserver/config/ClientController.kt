package com.yoonho.authserver.config

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

/**
 * @author yoonho
 * @since 2023.04.25
 */
@RestController
class ClientController(
    private val registeredClientRepository: RegisteredClientRepository
) {

    @GetMapping("/registeredClients")
    fun registeredClientList(): List<RegisteredClient?> {
        return listOf(
            registeredClientRepository.findByClientId("oauth2-client-app1"),
            registeredClientRepository.findByClientId("oauth2-client-app2"),
            registeredClientRepository.findByClientId("oauth2-client-app3"),
        )

    }
}