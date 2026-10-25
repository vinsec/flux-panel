package com.admin.controller;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;

/** Protocol clients must get real error statuses, not the UI's HTTP-200 R. */
@RestControllerAdvice(assignableTypes = EngineTrafficController.class)
@Order(Ordered.HIGHEST_PRECEDENCE)
public class EngineProtocolErrors {
    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<Map<String, String>> status(ResponseStatusException e) {
        return ResponseEntity.status(e.getStatus())
                .body(
                        Map.of(
                                "error",
                                e.getReason() == null
                                        ? "engine protocol rejected"
                                        : e.getReason()));
    }
}
