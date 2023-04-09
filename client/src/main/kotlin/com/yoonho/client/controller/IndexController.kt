package com.yoonho.client.controller

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

/**
 * @author yoonho
 * @since 2023.04.09
 */
@RestController
class IndexController {

    @GetMapping("/")
    fun index(): String =
        "index"
}