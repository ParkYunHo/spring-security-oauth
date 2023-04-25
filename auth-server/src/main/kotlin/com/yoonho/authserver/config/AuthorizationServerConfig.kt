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
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.web.SecurityFilterChain
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
@Configuration
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
        // OAuth2AuthorizationServerConfiguration 설정
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http)

        // 인증,인가 Exception 발생시 login페이지로 이동
        http
            .exceptionHandling { it.authenticationEntryPoint(LoginUrlAuthenticationEntryPoint("/login")) }

        // JWT를 위한 Resource Server 설정
        http
            .oauth2ResourceServer(OAuth2ResourceServerConfigurer<HttpSecurity>::jwt)

        return http.build()
    }

    /**
     * 공급자 정보 설정 (인가서버 정보)
     *
     * @author yoonho
     * @since 2023.04.25
     */
    @Bean
    fun settings(): AuthorizationServerSettings =
        AuthorizationServerSettings.builder().issuer("http://localhost:9000").build()

    /**
     * Client 정보 설정
     *
     * @author yoonho
     * @since 2023.04.25
     */
    @Bean
    fun registeredClientRepository(): RegisteredClientRepository {
        val client1 = this.getRegisteredClient(clientId = "oauth2-client-app1", clientSecret = "secret1")
        val client2 = this.getRegisteredClient(clientId = "oauth2-client-app2", clientSecret = "secret2")
        val client3 = this.getRegisteredClient(clientId = "oauth2-client-app3", clientSecret = "secret3")

        return InMemoryRegisteredClientRepository(listOf(client1, client2, client3))
    }

    private fun getRegisteredClient(clientId: String, clientSecret: String) =
        RegisteredClient.withId(UUID.randomUUID().toString())
            // Client 정보 설정
            .clientId(clientId)
            .clientSecret("{noop}$clientSecret")
            .clientName("clientId")
            .clientIdIssuedAt(Instant.now())
            .clientSecretExpiresAt(Instant.MAX)
            // Client 인증방식 설정
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
            // 권한부여방식 설정
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            // redirect_uri 설정
            .redirectUri("http://127.0.0.1:8080")   // localhost는 사용불가
            .redirectUri("http://127.0.0.1:8081")
            // scope 설정 (String 형태로 임의의 scope 설정 가능)
            .scope(OidcScopes.OPENID)
            .scope(OidcScopes.PROFILE)
            .scope(OidcScopes.EMAIL)
            .scope("read")
            .scope("write")
            .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())     // 동의화면을 제공할지 여부
            .build()


    /**
     * OpenID Connect를 위한 JWT Decoder 설정
     *
     * @author yoonho
     * @since 2023.04.25
     */
    @Bean
    fun jwtDecoder(jwkSource: JWKSource<SecurityContext>): JwtDecoder =
        OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)

    /**
     * JWK(JSON Web Key) 세트 설정
     *
     * @author yoonho
     * @since 2023.04.25
     */
    @Bean
    fun jwtSource(): JWKSource<SecurityContext> {
        val rsaKey = generateRsa()
        val jwkSet = JWKSet(rsaKey)

        return JWKSource { jwkSelector, context -> jwkSelector.select(jwkSet) }
    }

    /**
     * RSA Key 생성
     *
     * @author yoonho
     * @since 2023.04.25
     */
    private fun generateRsa(): RSAKey {
        val keyPair = generateRsaKey()
        val rsaPrivateKey = keyPair.private as RSAPrivateKey
        val rsaPublicKey = keyPair.public as RSAPublicKey

        return RSAKey.Builder(rsaPublicKey)
            .privateKey(rsaPrivateKey)
            .keyID(UUID.randomUUID().toString())    // key ID
            .build()
    }

    /**
     * RSA Key생성을 위한 비대칭키(KeyPair) 생성
     * <p>
     *     - 대칭키: 암호화, 복호화시 동일한 Key 사용
     *     - 비대칭키: 암호화, 복호화시 별도의 Key 사용 (일반적으로 암호화시 private key, 복호화시 public key 사용)
     *
     * @author yoonho
     * @since 2023.04.25
     */
    private fun generateRsaKey(): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")  // KeyPair 생성을 위한 알고리즘 설정 (RSA 알고리즘)
        keyPairGenerator.initialize(2048)   // KEY 길이 설정 (알고리즘에 정의된 단위를 따르며, 일반적으로 bit수)
        return keyPairGenerator.generateKeyPair()
    }
}