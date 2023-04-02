package com.yoonho.oauth.config

import org.slf4j.LoggerFactory
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.SecurityFilterChain

/**
 * @author yoonho
 * @since 2023.03.28
 */
@EnableWebSecurity
@Configuration
class SecurityConfig {
    private val log = LoggerFactory.getLogger(this::class.java)

//    /**
//     * 다중 SecurityFilterChain 구현
//     * <p>
//     *     - formLoginConfigure: FormLogin 설정
//     *     - httpBasicConfigure: HttpBasic 설정
//     *
//     * @author yoonho
//     * @since 2023.03.28
//     */
//    @Bean
//    fun formLoginConfigure(http: HttpSecurity): SecurityFilterChain {
//
//        http
//            .formLogin()
//
//        http
//            .authorizeHttpRequests()
//            .anyRequest().authenticated()
//
//        return http.build()
//    }
//
//    @Bean
//    fun httpBasicConfigure(http: HttpSecurity): SecurityFilterChain {
//
//        http
//            .httpBasic()
//
//        http
//            .authorizeHttpRequests()
//            .anyRequest().authenticated()
//
//        return http.build()
//    }
//    // :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

//    /**
//     * CustomSecurityConfigurer 구현
//     *
//     * @author yoonho
//     * @since 2023.03.28
//     */
//    @Bean
//    fun configure(http: HttpSecurity): SecurityFilterChain {
//
//        http
//            .formLogin()
//
//        http
//            .authorizeHttpRequests()
//            .anyRequest().authenticated()
//
//        http
//            .apply(CustomSecurityConfigurer().setFlag(false))
//
//        return http.build()
//    }
//    // :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

//    /**
//     * AuthenticationEntryPoint 설정
//     * <p>
//     *     - FormLogin, HttpBasic 둘다 설정하지 않은 경우, AuthenticationEntryPoint 호출됨
//     *     - FormLogin, HttpBasic 둘다 설정한 경우, Spring Security가 내부적으로 체크하여 FormLogin()을 호출함
//     *
//     * @author yoonho
//     * @since 2023.03.28
//     */
//    @Bean
//    fun configure(http: HttpSecurity): SecurityFilterChain {
//
//        http
//            .formLogin()
//        http
//            .httpBasic()
//
//        http
//            .exceptionHandling()
//            .authenticationEntryPoint { request, response, authException ->
//                // commence() 메서드 override
//                log.info(" >>> [commence] Custom EntryPoint!!")
//            }
//
//        http
//            .authorizeHttpRequests()
//            .anyRequest().authenticated()
//
//        return http.build()
//    }
//    // :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

    /**
     * Http Basic 구현
     *
     * @author yoonho
     * @since 2023.04.02
     */
    @Bean
    fun configure(http: HttpSecurity): SecurityFilterChain {
        http
            .httpBasic()
            .authenticationEntryPoint(CustomAuthenticationEntryPoint())

        http
            .authorizeHttpRequests()
            .anyRequest().authenticated()

        http
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

        return http.build()
    }
}