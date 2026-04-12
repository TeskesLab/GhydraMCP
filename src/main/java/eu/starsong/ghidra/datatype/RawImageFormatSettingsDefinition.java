package eu.starsong.ghidra.datatype;

import ghidra.docking.settings.EnumSettingsDefinition;
import ghidra.docking.settings.Settings;

public class RawImageFormatSettingsDefinition implements EnumSettingsDefinition {

    private static final String STORAGE_KEY = "raw_image_format";
    private static final String DISPLAY_NAME = "Pixel Format";
    private static final String DESCRIPTION = "Pixel format for raw image data (RGB565, 1bpp, etc.)";

    public static final int RGB565 = 0;
    public static final int RGB888 = 1;
    public static final int ARGB8888 = 2;
    public static final int RGB332 = 3;
    public static final int ARGB4444 = 4;
    public static final int GRAY_1BPP = 5;
    public static final int GRAY_2BPP = 6;
    public static final int GRAY_4BPP = 7;
    public static final int GRAY_8BPP = 8;

    private static final String[] CHOICES = {
        "RGB565",
        "RGB888",
        "ARGB8888",
        "RGB332",
        "ARGB4444",
        "1bpp Monochrome",
        "2bpp Grayscale",
        "4bpp Grayscale",
        "8bpp Grayscale"
    };

    public static final RawImageFormatSettingsDefinition DEF = new RawImageFormatSettingsDefinition();

    private RawImageFormatSettingsDefinition() {}

    @Override
    public int getChoice(Settings settings) {
        if (settings == null) return RGB565;
        Long val = settings.getLong(STORAGE_KEY);
        return val != null ? val.intValue() : RGB565;
    }

    @Override
    public void setChoice(Settings settings, int choice) {
        settings.setLong(STORAGE_KEY, choice);
    }

    @Override
    public String getValueString(Settings settings) {
        return CHOICES[getChoice(settings)];
    }

    @Override
    public String[] getDisplayChoices(Settings settings) {
        return CHOICES;
    }

    @Override
    public String getName() {
        return DISPLAY_NAME;
    }

    @Override
    public String getStorageKey() {
        return STORAGE_KEY;
    }

    @Override
    public String getDescription() {
        return DESCRIPTION;
    }

    @Override
    public String getDisplayChoice(int choice, Settings settings) {
        if (choice >= 0 && choice < CHOICES.length) {
            return CHOICES[choice];
        }
        return CHOICES[RGB565];
    }

    @Override
    public void clear(Settings settings) {
        settings.clearSetting(STORAGE_KEY);
    }

    @Override
    public void copySetting(Settings source, Settings dest) {
        Long val = source.getLong(STORAGE_KEY);
        if (val == null) {
            dest.clearSetting(STORAGE_KEY);
        } else {
            dest.setLong(STORAGE_KEY, val);
        }
    }

    @Override
    public boolean hasValue(Settings settings) {
        return settings.getValue(STORAGE_KEY) != null;
    }

    public static int getBytesPerPixel(int format) {
        switch (format) {
            case ARGB8888: return 4;
            case RGB888:   return 3;
            case RGB565:   return 2;
            case ARGB4444: return 2;
            case RGB332:   return 1;
            case GRAY_8BPP: return 1;
            case GRAY_4BPP: return 1;
            case GRAY_2BPP: return 1;
            case GRAY_1BPP: return 1;
            default:        return 2;
        }
    }

    public static int getBitsPerPixel(int format) {
        switch (format) {
            case ARGB8888: return 32;
            case RGB888:   return 24;
            case RGB565:   return 16;
            case ARGB4444: return 16;
            case RGB332:   return 8;
            case GRAY_8BPP: return 8;
            case GRAY_4BPP: return 4;
            case GRAY_2BPP: return 2;
            case GRAY_1BPP: return 1;
            default:        return 16;
        }
    }

    public static String getFormatName(int format) {
        if (format >= 0 && format < CHOICES.length) {
            return CHOICES[format];
        }
        return CHOICES[RGB565];
    }
}
