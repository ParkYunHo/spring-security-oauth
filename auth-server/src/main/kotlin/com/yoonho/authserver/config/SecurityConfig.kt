package com.yoonho.authserver.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain

/**
 * @author yoonho
 * @since 2023.04.25
 */
@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
class SecurityConfig {

    /**
     * 인가서버로 들어온 Request에 대한 기본설정
     *
     * @author yoonho
     * @since 2023.04.25
     */
    @Bean
    fun defaultConfigure(http: HttpSecurity): SecurityFilterChain {

//        http
//            .authorizeHttpRequests { it.anyRequest().authenticated() }

        http
            .formLogin()

        return http.build()
    }

    /**
     * 테스트 용도의 사용자 설정
     *
     * @author yoonho
     * @since 2023.04.25
     */
    @Bean
    fun userDetailService(): UserDetailsService {
        val user = User.withUsername("user")
            .password("{noop}1234")
            .authorities("ROLE_USER")
            .build()

        return InMemoryUserDetailsManager(user)
    }

    /**
     * 인증정보를 관리하는 서비스
     * <p>
     *     - 인가코드
     *     - access_token
     *     - refresh_token
     *     - openid
     *
     * @author yoonho
     * @since 2023.04.26
     */
    @Bean
    fun oAuth2AuthorizationService(): OAuth2AuthorizationService =
        InMemoryOAuth2AuthorizationService()
}