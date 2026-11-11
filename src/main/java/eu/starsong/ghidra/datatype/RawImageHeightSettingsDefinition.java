package eu.starsong.ghidra.datatype;

public class RawImageHeightSettingsDefinition extends RawImageDimensionSettingsDefinition {
    public static final RawImageHeightSettingsDefinition DEF = new RawImageHeightSettingsDefinition();

    private RawImageHeightSettingsDefinition() {
        super("raw_image_height", "Image Height", "Image height in pixels for raw image data types");
    }
}
