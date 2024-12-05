package com.artyomf.encryption;

import com.artyomf.encryption.rest.HeaderName;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class FileEncryptionTest {
    private static final String TEST_KEY = "33c1901c7f6ba9407df77a0c53e59e90fe1bcaffb680d2c6d28145416a0f7ce1";
    private static final String TEST_CONTENT = "test-content";

    @Autowired
    private MockMvc mvc;

    @Test
    void successfulEncryptionAndDecryptionTest() throws Exception {
        MvcResult encryptedMvcResult = mvc.perform(
                multipart(HttpMethod.POST, "/files/encrypt")
                        .file(prepareMockMultipartFile(TEST_CONTENT.getBytes()))
                        .header(HeaderName.ENCRYPTION_KEY, TEST_KEY)
                )
                .andExpect(status().isOk())
                .andExpect(header().exists(HeaderName.INITIALIZATION_VECTOR))
                .andReturn();

        byte[] encryptedTestContentBytes = encryptedMvcResult.getResponse().getContentAsByteArray();
        String iv = encryptedMvcResult.getResponse().getHeader(HeaderName.INITIALIZATION_VECTOR);

        MvcResult decryptedMvcResult = mvc.perform(
                multipart(HttpMethod.POST, "/files/decrypt")
                        .file(prepareMockMultipartFile(encryptedTestContentBytes))
                        .header(HeaderName.ENCRYPTION_KEY, TEST_KEY)
                        .header(HeaderName.INITIALIZATION_VECTOR, iv)
                )
                .andExpect(status().isOk())
                .andReturn();
        String decryptedTestContent = decryptedMvcResult.getResponse().getContentAsString();

        Assertions.assertEquals(TEST_CONTENT, decryptedTestContent);
    }

    @ParameterizedTest
    @ValueSource(strings = { "33c1901c7f6ba62e", "non-hex formatted" })
    void whenKeyHasWrongFormat_ThenBadRequest(String encryptionKey) throws Exception {
        mvc.perform(
                multipart(HttpMethod.POST, "/files/encrypt")
                        .file(prepareMockMultipartFile(TEST_CONTENT.getBytes()))
                        .header(HeaderName.ENCRYPTION_KEY, encryptionKey)
                )
                .andExpect(status().isBadRequest());
    }

    @Test
    void whenIVHasWrongSize_ThenBadRequest() throws Exception {
        mvc.perform(
                multipart(HttpMethod.POST, "/files/decrypt")
                        .file(prepareMockMultipartFile(TEST_CONTENT.getBytes()))
                        .header(HeaderName.ENCRYPTION_KEY, TEST_KEY)
                        .header(HeaderName.INITIALIZATION_VECTOR, "ff")
                )
                .andExpect(status().isBadRequest());
    }

    private MockMultipartFile prepareMockMultipartFile(byte[] content) {
        return new MockMultipartFile(
                "file",
                "mock-file.txt",
                MediaType.TEXT_PLAIN_VALUE,
                content
        );
    }
}
