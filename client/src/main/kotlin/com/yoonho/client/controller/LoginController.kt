package com.yoonho.client.controller

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

/**
 * @author yoonho
 * @since 2023.04.11
 */
@RestController
class LoginController {

    @GetMapping("/loginPage")
    fun loginPage(): String =
        "loginPage"
}