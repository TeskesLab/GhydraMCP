package eu.starsong.ghidra.datatype;

import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.model.data.BuiltIn;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataImage;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Dynamic;
import ghidra.program.model.data.Resource;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;

import javax.swing.ImageIcon;
import java.awt.image.BufferedImage;

public class RawImageDataType extends BuiltIn implements Dynamic, Resource {

    private static final long serialVersionUID = 1L;

    private static final SettingsDefinition[] SETTINGS_DEFS = {
        RawImageWidthSettingsDefinition.DEF,
        RawImageHeightSettingsDefinition.DEF,
        RawImageFormatSettingsDefinition.DEF
    };

    public RawImageDataType() {
        this(null);
    }

    public RawImageDataType(DataTypeManager dtm) {
        super(CategoryPath.ROOT, "RawImage", dtm);
    }

    @Override
    protected SettingsDefinition[] getBuiltInSettingsDefinitions() {
        return SETTINGS_DEFS;
    }

    @Override
    public String getDescription() {
        return "Raw image data (no header). Configure width, height, and pixel format in settings.";
    }

    @Override
    public String getMnemonic(Settings settings) {
        return "RawImage";
    }

    @Override
    public int getLength() {
        return -1;
    }

    @Override
    public int getLength(MemBuffer buf, int maxLength) {
        return maxLength;
    }

    @Override
    public boolean canSpecifyLength() {
        return false;
    }

    @Override
    public DataType getReplacementBaseType() {
        return this;
    }

    @Override
    public Object getValue(MemBuffer buf, Settings settings, int length) {
        int width = (int) RawImageWidthSettingsDefinition.DEF.getValue(settings);
        int height = (int) RawImageHeightSettingsDefinition.DEF.getValue(settings);
        int format = RawImageFormatSettingsDefinition.DEF.getChoice(settings);

        if (width <= 0 || height <= 0) {
            return null;
        }

        int bytesPerRow = computeBytesPerRow(width, format);
        int totalBytes = bytesPerRow * height;

        if (totalBytes > length) {
            Msg.warn(this, "RawImage: not enough data for " + width + "x" + height +
                " (" + RawImageFormatSettingsDefinition.getFormatName(format) + "), need " +
                totalBytes + " bytes, have " + length);
            totalBytes = length;
            height = totalBytes / bytesPerRow;
            if (height <= 0) return null;
        }

        byte[] raw = new byte[totalBytes];
        for (int i = 0; i < totalBytes; i++) {
            try {
                raw[i] = (byte) buf.getUnsignedByte(i);
            } catch (MemoryAccessException e) {
                break;
            }
        }

        BufferedImage image = decodeImage(raw, width, height, format, bytesPerRow);
        if (image == null) return null;

        String desc = "<RawImage " + width + "x" + height + " " +
            RawImageFormatSettingsDefinition.getFormatName(format) + ">";

        return new RawDataImage(image, desc, "png");
    }

    @Override
    public Class<?> getValueClass(Settings settings) {
        return DataImage.class;
    }

    @Override
    public String getRepresentation(MemBuffer buf, Settings settings, int length) {
        int width = (int) RawImageWidthSettingsDefinition.DEF.getValue(settings);
        int height = (int) RawImageHeightSettingsDefinition.DEF.getValue(settings);
        int format = RawImageFormatSettingsDefinition.DEF.getChoice(settings);
        if (width <= 0 || height <= 0) {
            return "<RawImage: configure width/height>";
        }
        return "<RawImage " + width + "x" + height + " " +
            RawImageFormatSettingsDefinition.getFormatName(format) + ">";
    }

    @Override
    public String getDefaultLabelPrefix() {
        return "IMG";
    }

    @Override
    public DataType clone(DataTypeManager dtm) {
        return new RawImageDataType(dtm);
    }

    static int computeBytesPerRow(int width, int format) {
        int bitsPerPixel = RawImageFormatSettingsDefinition.getBytesPerPixel(format) * 8;
        int totalBits = width * RawImageFormatSettingsDefinition.getBitsPerPixel(format);
        return (totalBits + 7) / 8;
    }

    static BufferedImage decodeImage(byte[] raw, int width, int height, int format, int bytesPerRow) {
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);

        switch (format) {
            case RawImageFormatSettingsDefinition.RGB565:
                decodeRGB565(raw, image, width, height, bytesPerRow);
                break;
            case RawImageFormatSettingsDefinition.RGB888:
                decodeRGB888(raw, image, width, height, bytesPerRow);
                break;
            case RawImageFormatSettingsDefinition.ARGB8888:
                decodeARGB8888(raw, image, width, height, bytesPerRow);
                break;
            case RawImageFormatSettingsDefinition.RGB332:
                decodeRGB332(raw, image, width, height, bytesPerRow);
                break;
            case RawImageFormatSettingsDefinition.ARGB4444:
                decodeARGB4444(raw, image, width, height, bytesPerRow);
                break;
            case RawImageFormatSettingsDefinition.GRAY_1BPP:
                decodeGrayscale(raw, image, width, height, bytesPerRow, 1);
                break;
            case RawImageFormatSettingsDefinition.GRAY_2BPP:
                decodeGrayscale(raw, image, width, height, bytesPerRow, 2);
                break;
            case RawImageFormatSettingsDefinition.GRAY_4BPP:
                decodeGrayscale(raw, image, width, height, bytesPerRow, 4);
                break;
            case RawImageFormatSettingsDefinition.GRAY_8BPP:
                decodeGrayscale(raw, image, width, height, bytesPerRow, 8);
                break;
            default:
                return null;
        }

        return image;
    }

    static void decodeRGB565(byte[] raw, BufferedImage image, int width, int height, int bytesPerRow) {
        for (int y = 0; y < height; y++) {
            int rowOffset = y * bytesPerRow;
            for (int x = 0; x < width; x++) {
                int offset = rowOffset + x * 2;
                if (offset + 1 >= raw.length) break;
                int pixel = ((raw[offset] & 0xFF) << 8) | (raw[offset + 1] & 0xFF);
                int r = ((pixel >> 11) & 0x1F) * 255 / 31;
                int g = ((pixel >> 5) & 0x3F) * 255 / 63;
                int b = (pixel & 0x1F) * 255 / 31;
                image.setRGB(x, y, (0xFF << 24) | (r << 16) | (g << 8) | b);
            }
        }
    }

    static void decodeRGB888(byte[] raw, BufferedImage image, int width, int height, int bytesPerRow) {
        for (int y = 0; y < height; y++) {
            int rowOffset = y * bytesPerRow;
            for (int x = 0; x < width; x++) {
                int offset = rowOffset + x * 3;
                if (offset + 2 >= raw.length) break;
                int r = raw[offset] & 0xFF;
                int g = raw[offset + 1] & 0xFF;
                int b = raw[offset + 2] & 0xFF;
                image.setRGB(x, y, (0xFF << 24) | (r << 16) | (g << 8) | b);
            }
        }
    }

    static void decodeARGB8888(byte[] raw, BufferedImage image, int width, int height, int bytesPerRow) {
        for (int y = 0; y < height; y++) {
            int rowOffset = y * bytesPerRow;
            for (int x = 0; x < width; x++) {
                int offset = rowOffset + x * 4;
                if (offset + 3 >= raw.length) break;
                int a = raw[offset] & 0xFF;
                int r = raw[offset + 1] & 0xFF;
                int g = raw[offset + 2] & 0xFF;
                int b = raw[offset + 3] & 0xFF;
                image.setRGB(x, y, (a << 24) | (r << 16) | (g << 8) | b);
            }
        }
    }

    static void decodeRGB332(byte[] raw, BufferedImage image, int width, int height, int bytesPerRow) {
        for (int y = 0; y < height; y++) {
            int rowOffset = y * bytesPerRow;
            for (int x = 0; x < width; x++) {
                int offset = rowOffset + x;
                if (offset >= raw.length) break;
                int pixel = raw[offset] & 0xFF;
                int r = ((pixel >> 5) & 0x07) * 255 / 7;
                int g = ((pixel >> 2) & 0x07) * 255 / 7;
                int b = (pixel & 0x03) * 255 / 3;
                image.setRGB(x, y, (0xFF << 24) | (r << 16) | (g << 8) | b);
            }
        }
    }

    static void decodeARGB4444(byte[] raw, BufferedImage image, int width, int height, int bytesPerRow) {
        for (int y = 0; y < height; y++) {
            int rowOffset = y * bytesPerRow;
            for (int x = 0; x < width; x++) {
                int offset = rowOffset + x * 2;
                if (offset + 1 >= raw.length) break;
                int pixel = ((raw[offset] & 0xFF) << 8) | (raw[offset + 1] & 0xFF);
                int a = ((pixel >> 12) & 0x0F) * 255 / 15;
                int r = ((pixel >> 8) & 0x0F) * 255 / 15;
                int g = ((pixel >> 4) & 0x0F) * 255 / 15;
                int b = (pixel & 0x0F) * 255 / 15;
                image.setRGB(x, y, (a << 24) | (r << 16) | (g << 8) | b);
            }
        }
    }

    static void decodeGrayscale(byte[] raw, BufferedImage image, int width, int height, int bytesPerRow, int bpp) {
        int pixelsPerByte = 8 / bpp;
        int mask = (1 << bpp) - 1;

        for (int y = 0; y < height; y++) {
            int rowOffset = y * bytesPerRow;
            for (int x = 0; x < width; x++) {
                int byteIndex = rowOffset + (x / pixelsPerByte);
                int bitOffset = (pixelsPerByte - 1 - (x % pixelsPerByte)) * bpp;
                if (byteIndex >= raw.length) break;

                int gray = (raw[byteIndex] >> bitOffset) & mask;
                int val = gray * 255 / mask;
                image.setRGB(x, y, (0xFF << 24) | (val << 16) | (val << 8) | val);
            }
        }
    }

    static class RawDataImage extends DataImage {

        private final BufferedImage image;
        private final String fileType;

        RawDataImage(BufferedImage image, String description, String fileType) {
            setDescription(description);
            this.image = image;
            this.fileType = fileType;
        }

        @Override
        public ImageIcon getImageIcon() {
            return new ImageIcon(image);
        }

        @Override
        public String getImageFileType() {
            return fileType;
        }
    }
}
