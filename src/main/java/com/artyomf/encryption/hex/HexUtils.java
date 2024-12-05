package com.artyomf.encryption.hex;

import java.util.HexFormat;

public final class HexUtils {
    private HexUtils() {
    }

    public static byte[] fromHexFormatOrThrow(String hexString, String message) {
        try {
            return HexFormat.of().parseHex(hexString);
        } catch (Exception e) {
            throw new HexFormatException(message);
        }
    }

    public static String toHexFormat(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }
}
