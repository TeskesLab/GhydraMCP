package eu.starsong.ghidra.datatype;

import ghidra.docking.settings.Settings;
import ghidra.docking.settings.NumberSettingsDefinition;

import java.math.BigInteger;

public class RawImageWidthSettingsDefinition implements NumberSettingsDefinition {

    private static final String STORAGE_KEY = "raw_image_width";
    private static final String DISPLAY_NAME = "Image Width";
    private static final String DESCRIPTION = "Image width in pixels for raw image data types";
    private static final BigInteger MAX_VALUE = BigInteger.valueOf(0xFFFF);
    private static final int DEFAULT = 0;

    public static final RawImageWidthSettingsDefinition DEF = new RawImageWidthSettingsDefinition();

    private RawImageWidthSettingsDefinition() {}

    @Override
    public BigInteger getMaxValue() {
        return MAX_VALUE;
    }

    @Override
    public boolean allowNegativeValue() {
        return false;
    }

    @Override
    public boolean isHexModePreferred() {
        return false;
    }

    @Override
    public long getValue(Settings settings) {
        if (settings == null) return DEFAULT;
        Long val = settings.getLong(STORAGE_KEY);
        return val != null ? val : DEFAULT;
    }

    @Override
    public void setValue(Settings settings, long value) {
        if (value == DEFAULT) {
            settings.clearSetting(STORAGE_KEY);
        } else {
            settings.setLong(STORAGE_KEY, value);
        }
    }

    @Override
    public boolean hasValue(Settings settings) {
        return getValue(settings) != DEFAULT;
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
}
