package com.eazybytes.entity;

import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

/**
 * redirect test용
 */
@Getter
public class SessionExpireEntity {
    private LocalDateTime time;
    private String message;
    private String cause;

    public SessionExpireEntity() {
    }

    public SessionExpireEntity(LocalDateTime time, String message, String cause) {
        this.time = time;
        this.message = message;
        this.cause = cause;
    }
}
