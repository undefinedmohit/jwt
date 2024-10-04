package com.testJWT.jwt.Controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HealthCheck {

    @GetMapping("/health-check")
    String heathCheck()
    {
        return "I'm working fine";
    }
}
