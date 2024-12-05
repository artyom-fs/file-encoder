package com.artyomf.encryption.rest;

import com.artyomf.encryption.cipher.CipherProvider;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.InputStreamResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import java.io.IOException;
import java.io.InputStream;

import static com.artyomf.encryption.hex.HexUtils.fromHexFormatOrThrow;
import static com.artyomf.encryption.hex.HexUtils.toHexFormat;

@RestController
@Slf4j
@Tag(name = "File encryption / decryption API")
public class FileEncryptionController {
    private final CipherProvider cipherProvider;

    public FileEncryptionController(CipherProvider cipherProvider) {
        this.cipherProvider = cipherProvider;
    }

    @PostMapping(
            value = "/files/encrypt",
            consumes = MediaType.MULTIPART_FORM_DATA_VALUE,
            produces = MediaType.APPLICATION_OCTET_STREAM_VALUE
    )
    @Operation(summary = "File encryption", description = "Returns encrypted file")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successfully encrypted"),
            @ApiResponse(responseCode = "400", description = "Encryption key has wrong format")
    })
    public ResponseEntity<InputStreamResource> encryptFile(
            @RequestParam("file") MultipartFile file,
            @Parameter(
                    name = HeaderName.ENCRYPTION_KEY,
                    description = "Encryption Key in HexFormat",
                    example = "33c1901c7f6ba9407df77a0c53e59e90fe1bcaffb680d2c6d28145416a0f7ce1"
            )
            @RequestHeader(HeaderName.ENCRYPTION_KEY) String hexKey
    ) throws IOException {
        log.info(
                "Received File encryption request; fileName={}, fileSize={}",
                file.getOriginalFilename(),
                file.getSize()
        );
        byte[] keyBytes = fromHexFormatOrThrow(hexKey, "Key format does not match HexFormat");
        Cipher cipher = cipherProvider.provideCipherForEncryption(keyBytes);
        InputStream contentStream = file.getInputStream();
        CipherInputStream encryptedContentStream = new CipherInputStream(contentStream, cipher);
        return ResponseEntity.ok()
                .header(
                        HttpHeaders.CONTENT_DISPOSITION,
                        String.format("attachment; filename=enc_%s", file.getOriginalFilename())
                )
                .header(HeaderName.INITIALIZATION_VECTOR, toHexFormat(cipher.getIV()))
                .body(new InputStreamResource(encryptedContentStream));
    }

    @PostMapping(
            value = "/files/decrypt",
            consumes = MediaType.MULTIPART_FORM_DATA_VALUE,
            produces = MediaType.APPLICATION_OCTET_STREAM_VALUE
    )
    @Operation(summary = "File decryption", description = "Returns decrypted file")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successfully decrypted"),
            @ApiResponse(responseCode = "400", description = "Encryption key or IV has wrong format")
    })
    public ResponseEntity<Resource> getDecryptedFile(
            @RequestParam("file") MultipartFile file,
            @Parameter(
                    name = HeaderName.ENCRYPTION_KEY,
                    description = "Decryption Key in HexFormat",
                    example = "33c1901c7f6ba9407df77a0c53e59e90fe1bcaffb680d2c6d28145416a0f7ce1"
            )
            @RequestHeader(HeaderName.ENCRYPTION_KEY) String hexKey,
            @Parameter(
                    name = HeaderName.INITIALIZATION_VECTOR,
                    description = "Initialization Vector in HexFormat that was returned after encryption",
                    example = "7b10674dd73159f726fc61d94106cf84"
            )
            @RequestHeader(HeaderName.INITIALIZATION_VECTOR) String initializationVector
    ) throws IOException {
        log.info(
                "Received File decryption request; fileName={}, fileSize={}",
                file.getOriginalFilename(),
                file.getSize()
        );
        byte[] keyBytes = fromHexFormatOrThrow(hexKey, "Key format does not match HexFormat");
        byte[] ivBytes = fromHexFormatOrThrow(initializationVector, "IV format does not match HexFormat");
        Cipher cipher = cipherProvider.provideCipherForDecryption(keyBytes, ivBytes);
        InputStream contentStream = file.getInputStream();
        CipherInputStream decryptedContentStream = new CipherInputStream(contentStream, cipher);
        return ResponseEntity.ok()
                .header(
                        HttpHeaders.CONTENT_DISPOSITION,
                        String.format("attachment; filename=dec_%s", file.getOriginalFilename())
                )
                .body(new InputStreamResource(decryptedContentStream));
    }
}
