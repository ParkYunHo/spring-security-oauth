//package com.yoonho.authorization.config
//
//import org.springframework.context.annotation.Bean
//import org.springframework.context.annotation.Configuration
//import org.springframework.context.annotation.Import
//import org.springframework.security.config.annotation.web.builders.HttpSecurity
//import org.springframework.security.oauth2.core.AuthorizationGrantType
//import org.springframework.security.oauth2.core.ClientAuthenticationMethod
//import org.springframework.security.oauth2.core.oidc.OidcScopes
//import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
//import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
//import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationEndpointConfigurer
//import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
//import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
//import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
//import org.springframework.security.web.SecurityFilterChain
//import java.util.*
//
///**
// * 사용자 정의 방식
// *
// * @author yoonho
// * @since 2023.04.24
// */
//@Configuration
//class AuthServerConfig3 {
//
//    @Bean
//    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
//        val configurer = OAuth2AuthorizationServerConfigurer()
//        http.apply(configurer)
//
//        return http.build()
//    }
//
//    @Bean
//    fun providerSettings(): AuthorizationServerSettings =
//        AuthorizationServerSettings.builder().issuer("http://127.0.0.1:9000").build()   // 인가서버 도메인
//
//    @Bean
//    fun registeredClientRepository(): RegisteredClientRepository {
//        val registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
//            .clientId("oauth2-client-app")
//            .clientSecret("{noop}secret")
//            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//            .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
//            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
//            .redirectUri("http://127.0.0.1:8081/login/oauth2/code/oauth2-client-app")
//            .redirectUri("http://127.0.0.1:8081")
//            .scope(OidcScopes.OPENID)
//            .scope("message.read")
//            .scope("message.write")
//            .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
//            .build()
//
//        return InMemoryRegisteredClientRepository(registeredClient)
//    }
//
//}