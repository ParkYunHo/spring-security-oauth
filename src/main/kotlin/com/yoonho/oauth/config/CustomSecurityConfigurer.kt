package com.yoonho.oauth.config

import org.slf4j.LoggerFactory
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer

/**
 * @author yoonho
 * @since 2023.03.28
 */
class CustomSecurityConfigurer: AbstractHttpConfigurer<CustomSecurityConfigurer, HttpSecurity>() {
    // AbstractHttpConfigurer<T, B>
    // T: Configurer 클래스를 의미, 따라서 별도로 작업할 CustomSecurityConfigurer로 설정
    // B: HttpSecurity를 의미

    private val log = LoggerFactory.getLogger(this::class.java)

    private var isSecure: Boolean = false;

    override fun init(builder: HttpSecurity?) {
        super.init(builder)
        log.info(" >>> [init] init method started!!!")
    }

    override fun configure(builder: HttpSecurity?) {
        super.configure(builder)
        log.info(" >>> [configure] configure method started!!!")

        if(isSecure)
            log.info("https is required")
        else
            log.info("https is optional")
    }

    fun setFlag(isSecure: Boolean): CustomSecurityConfigurer {
        this.isSecure = isSecure
        return this
    }
}