package com.artyomf.encryption.rest;

import com.artyomf.encryption.cipher.EncryptionException;
import com.artyomf.encryption.hex.HexFormatException;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.io.IOException;

@ControllerAdvice
public class FileControllerAdvice {
    @ExceptionHandler({ EncryptionException.class, HexFormatException.class })
    public ResponseEntity<String> handleEncryptionException(Exception e) {
        return ResponseEntity.badRequest().body(e.getMessage());
    }

    @ExceptionHandler(IOException.class)
    public ResponseEntity<String> handleException() {
        return ResponseEntity.internalServerError().body("Internal io error");
    }
}
