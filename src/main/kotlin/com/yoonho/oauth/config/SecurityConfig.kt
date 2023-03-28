package com.yoonho.oauth.config

import org.slf4j.LoggerFactory
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.web.SecurityFilterChain

/**
 * @author yoonho
 * @since 2023.03.28
 */
@EnableWebSecurity
@Configuration
class SecurityConfig {
    private val log = LoggerFactory.getLogger(this::class.java)

    @Bean
    fun configure(http: HttpSecurity): SecurityFilterChain {

        http
            .formLogin()

        http
            .authorizeHttpRequests()
            .anyRequest().authenticated()

        http
            .apply(CustomSecurityConfigurer().setFlag(false))

        return http.build()
    }
}