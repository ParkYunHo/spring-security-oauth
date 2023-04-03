package com.yoonho.cors1.controller

import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping

/**
 * @author yoonho
 * @since 2023.04.03
 */
@Controller
class Cors1Controller {

    @GetMapping("/")
    fun index(): String =
        "index"
}