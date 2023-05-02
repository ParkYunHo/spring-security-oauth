package com.yoonho.authserver.config

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.AuthenticationConverter
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.time.Instant
import java.util.*

/**
 * @author yoonho
 * @since 2023.04.25
 */
@Configuration(proxyBeanMethods = false)
class AuthorizationServerConfig {

    /**
     * 인가서버 설정
     *
     * @author yoonho
     * @since 2023.04.25
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)  // 우선적으로 해당 Bean이 실행되도록 설정
    fun authConfigure(http: HttpSecurity): SecurityFilterChain {
        val authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer()
        val endpointsMatcher = authorizationServerConfigurer.endpointsMatcher

        // 인가코드 관련 설정
        authorizationServerConfigurer
            .authorizationEndpoint {
                // 에러 핸들러
                it.errorResponseHandler { request, response, exception ->

                }
                it.authorizationResponseHandler { request, response, authentication ->

                }
                it.authenticationProvider(null)
            }

        http
            .securityMatcher(endpointsMatcher)
            .authorizeHttpRequests { it.anyRequest().authenticated() }
            .csrf { it.ignoringRequestMatchers(endpointsMatcher) }
            .apply(authorizationServerConfigurer)


        // 인증,인가 Exception 발생시 login페이지로 이동
        http
            .exceptionHandling { it.authenticationEntryPoint(LoginUrlAuthenticationEntryPoint("/login")) }

        // JWT를 위한 Resource Server 설정
        http
            .oauth2ResourceServer(OAuth2ResourceServerConfigurer<HttpSecurity>::jwt)

        return http.build()
    }


}