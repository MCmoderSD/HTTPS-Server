package de.MCmoderSD.server.enums;

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
}