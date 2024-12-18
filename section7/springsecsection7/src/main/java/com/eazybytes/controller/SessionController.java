package com.eazybytes.controller;

import com.eazybytes.entity.SessionExpireEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;

import static org.springframework.http.HttpStatus.*;

/**
 * test controller
 */
@Controller
public class SessionController {
    @GetMapping("/invalidSession")
    public ResponseEntity<SessionExpireEntity> sessionExpire() {
        SessionExpireEntity se = new SessionExpireEntity(LocalDateTime.now(), "Session Expired", "timeout");
        return new ResponseEntity<>(se, FORBIDDEN);
    }
}
