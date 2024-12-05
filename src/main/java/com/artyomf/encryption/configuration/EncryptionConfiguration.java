package com.artyomf.encryption.configuration;

import com.artyomf.encryption.cipher.CipherProvider;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class EncryptionConfiguration {
    @Bean
    public CipherProvider cipherProvider(@Value("${encryption.algorithm}") String algorithm) {
        return new CipherProvider(algorithm);
    }
}
