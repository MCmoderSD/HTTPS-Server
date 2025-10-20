package de.MCmoderSD.server.enums;

@SuppressWarnings("unused")
public enum KeySize {

    // RSA Key Sizes
    RSA_2048(2048),
    RSA_3072(3072),
    RSA_4096(4096);

    // Attributes
    private final int size;

    // Constructor
    KeySize(int size) {
        this.size = size;
    }

    // Getter
    public int getSize() {
        return size;
    }

    // Static Methods
    public static boolean isValidSize(int size) {
        return size == RSA_2048.getSize() || size == RSA_3072.getSize() || size == RSA_4096.getSize();
    }

    public static KeySize getKeySize(int size) {
        return switch (size) {
            case 2048 -> RSA_2048;
            case 3072 -> RSA_3072;
            case 4096 -> RSA_4096;
            default -> throw new IllegalArgumentException("Invalid key size: " + size);
        };
    }

    public static KeySize getKeySize(String keySize) {
        if (keySize == null || keySize.isBlank()) throw new IllegalArgumentException("Key size cannot be null or empty");
        try {
            return getKeySize(Integer.parseInt(keySize));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid key size: " + keySize, e);
        }
    }
}