package com.yoonho.cors2.controller

import com.yoonho.cors2.domain.User
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

/**
 * @author yoonho
 * @since 2023.04.03
 */
@RestController
class Cors2Controller {

    @GetMapping("/api/users")
    fun users(): User =
        User("user", 20)

}