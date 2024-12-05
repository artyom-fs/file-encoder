package com.artyomf.encryption.cipher;

public class EncryptionException extends RuntimeException {
    public EncryptionException(Type type, Throwable cause) {
        super(type.message(), cause);
    }

    public enum Type {
        /**
         * This type should be thrown if a key has wrong format or size
         */
        INVALID_KEY("Invalid key format"),
        /**
         * This type should be thrown if params (e.g. IV) are not valid (for IV - wrong size)
         */
        INVALID_PARAMS("Invalid cipher parameters");

        private final String message;

        Type(String message) {
            this.message = message;
        }

        public String message() {
            return message;
        }
    }
}
