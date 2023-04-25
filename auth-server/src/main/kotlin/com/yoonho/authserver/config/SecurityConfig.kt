package com.yoonho.authserver.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain

/**
 * @author yoonho
 * @since 2023.04.25
 */
@EnableWebSecurity
@Configuration
class SecurityConfig {

    /**
     * 인가서버로 들어온 Request에 대한 기본설정
     *
     * @author yoonho
     * @since 2023.04.25
     */
    @Bean
    fun configure(http: HttpSecurity): SecurityFilterChain {

        http
            .authorizeHttpRequests { it.anyRequest().authenticated() }

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
}