package eu.starsong.ghidra.datatype;

import ghidra.docking.settings.NumberSettingsDefinition;
import ghidra.docking.settings.Settings;

import java.math.BigInteger;

abstract class RawImageDimensionSettingsDefinition implements NumberSettingsDefinition {
    private static final BigInteger MAX_VALUE = BigInteger.valueOf(0xFFFF);
    private final String storageKey;
    private final String displayName;
    private final String description;

    RawImageDimensionSettingsDefinition(String storageKey, String displayName, String description) {
        this.storageKey = storageKey;
        this.displayName = displayName;
        this.description = description;
    }

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
        if (settings == null) return 0;
        Long value = settings.getLong(storageKey);
        return value != null ? value : 0;
    }

    @Override
    public void setValue(Settings settings, long value) {
        if (value == 0) {
            settings.clearSetting(storageKey);
        } else {
            settings.setLong(storageKey, value);
        }
    }

    @Override
    public boolean hasValue(Settings settings) {
        return getValue(settings) != 0;
    }

    @Override
    public String getName() {
        return displayName;
    }

    @Override
    public String getStorageKey() {
        return storageKey;
    }

    @Override
    public String getDescription() {
        return description;
    }

    @Override
    public void clear(Settings settings) {
        settings.clearSetting(storageKey);
    }

    @Override
    public void copySetting(Settings source, Settings destination) {
        Long value = source.getLong(storageKey);
        if (value == null) {
            destination.clearSetting(storageKey);
        } else {
            destination.setLong(storageKey, value);
        }
    }
}
