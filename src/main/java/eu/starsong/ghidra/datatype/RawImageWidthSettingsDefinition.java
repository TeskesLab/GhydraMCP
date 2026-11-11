package eu.starsong.ghidra.datatype;

public class RawImageWidthSettingsDefinition extends RawImageDimensionSettingsDefinition {
    public static final RawImageWidthSettingsDefinition DEF = new RawImageWidthSettingsDefinition();

    private RawImageWidthSettingsDefinition() {
        super("raw_image_width", "Image Width", "Image width in pixels for raw image data types");
    }
}
