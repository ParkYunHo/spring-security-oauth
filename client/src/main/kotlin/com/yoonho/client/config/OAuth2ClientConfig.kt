package com.yoonho.client.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.registration.ClientRegistrations
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository
import org.springframework.security.web.SecurityFilterChain

/**
 * @author yoonho
 * @since 2023.04.10
 */
@EnableWebSecurity
@Configuration
class OAuth2ClientConfig {

    /**
     * ClientRegistrationRepository Bean 설정
     * <p>
     *     - default repository 구현체인 InMemoryClientRegistrationRepository 방식 사용
     *
     * @author yoonho
     * @since 2023.04.10
     */
    @Bean
    fun clientRegistrationRepository(): ClientRegistrationRepository =
        InMemoryClientRegistrationRepository(keyCloackClientRegistration())

    /**
     * ClientRegistration 설정
     * <p>
     *     - ClientRegistrations() 메서드를 통해 OAUTH 또는 OIDC 인가서버 메타데이터를 조회할 수 있다.
     *
     * @author yoonho
     * @since 2023.04.10
     */
    private fun keyCloackClientRegistration(): ClientRegistration =
        ClientRegistrations.fromIssuerLocation("http://localhost:8081/realms/oauth2")
            .registrationId("keycloak")
            .clientId("oauth2-client-app")
            .clientSecret("oTzOtDvPQr7R2yxtJKOHN4gB3FNTKpfw")
            .redirectUri("http://localhost:8080/login/oauth2/code/keycloak")
            .build()

    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .authorizeHttpRequests()
            .anyRequest().authenticated()

        http
            .oauth2Client()

        return http.build()
    }
}