"""Raw image definition commands."""

import click

from ..client.exceptions import GhidraError
from ..utils import should_page, page_output, rich_echo, validate_address


FORMAT_MAP = {
    "rgb565": 0, "rgb888": 1, "argb8888": 2, "rgb332": 3,
    "argb4444": 4, "1bpp": 5, "2bpp": 6, "4bpp": 7, "8bpp": 8,
    "1bpp_monochrome": 5, "2bpp_grayscale": 6, "4bpp_grayscale": 7, "8bpp_grayscale": 8,
}

FORMAT_DISPLAY_NAMES = {
    "1bpp_monochrome": "1bpp Monochrome",
    "2bpp_grayscale": "2bpp Grayscale",
    "4bpp_grayscale": "4bpp Grayscale",
    "8bpp_grayscale": "8bpp Grayscale",
}

BPP_MAP = {0: 16, 1: 24, 2: 32, 3: 8, 4: 16, 5: 1, 6: 2, 7: 4, 8: 8}


@click.group('raw-image')
def raw_image():
    """Raw image data commands.

    Commands for defining raw image data that renders inline in Ghidra's Listing view.
    """
    pass


@raw_image.command('define')
@click.option('--address', '-a', required=True, help='Memory address where raw image data starts (hex)')
@click.option('--width', type=int, required=True, help='Image width in pixels')
@click.option('--height', type=int, required=True, help='Image height in pixels')
@click.option('--format', 'pixel_format', default='RGB565',
              type=click.Choice(['RGB565', 'RGB888', 'ARGB8888', 'RGB332', 'ARGB4444',
                                 '1bpp', '1bpp_Monochrome', '2bpp', '2bpp_Grayscale',
                                 '4bpp', '4bpp_Grayscale', '8bpp', '8bpp_Grayscale']),
              help='Pixel format (default: RGB565)')
@click.option('--endian', type=click.Choice(['little', 'big']), default='little', help='Byte order (default: little)')
@click.pass_context
def define(ctx, address, width, height, pixel_format, endian):
    """Define a raw image at the specified address.

    Creates a RawImage data type at the address with the given dimensions and
    pixel format. The image will render inline in Ghidra's Listing view.

    Requires PyGhidra support in Ghidra (launch via 'pyghidraRun').

    \b
    Supported formats:
        RGB565, RGB888, ARGB8888, RGB332, ARGB4444,
        1bpp Monochrome, 2bpp Grayscale, 4bpp Grayscale, 8bpp Grayscale

    \b
    Examples:
        ghydra raw-image define --address 0x401000 --width 128 --height 64 --format RGB565
        ghydra raw-image define -a 0x402000 --width 320 --height 240 --format ARGB8888 --endian big
    """
    if width <= 0 or height <= 0:
        rich_echo("[red]Error:[/red] Width and height must be positive integers", err=True)
        ctx.exit(1)

    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    fmt_lower = pixel_format.lower().replace("-", "_")
    if fmt_lower not in FORMAT_MAP:
        rich_echo(f"[red]Error:[/red] Unknown pixel format '{pixel_format}'", err=True)
        ctx.exit(1)

    fmt_ordinal = FORMAT_MAP[fmt_lower]
    display_name = FORMAT_DISPLAY_NAMES.get(fmt_lower, fmt_lower.upper())
    validated_addr = validate_address(address)

    bpp = BPP_MAP.get(fmt_ordinal, 16)
    byte_len = (width * height * bpp + 7) // 8

    script = f"""from ghidra.program.model.data import BuiltInDataTypeManager

dtm = BuiltInDataTypeManager.getDataTypeManager()
dt = dtm.getDataType("/RawImage")
if dt is None:
    raise RuntimeError("RawImage not found in built-in types")

addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress("{validated_addr}")
listing = currentProgram.getListing()

tx = currentProgram.startTransaction("define_raw_image")
try:
    listing.clearCodeUnits(addr, addr.add({byte_len - 1}), False)
    d = listing.createData(addr, dt, {byte_len})
    if d is not None:
        d.setValue("raw_image_width", {width})
        d.setValue("raw_image_height", {height})
        d.setValue("raw_image_format", {fmt_ordinal})
        print("OK: RawImage {width}x{height} {display_name} at " + str(addr) + " (" + str(d.getLength()) + " bytes)")
    else:
        print("ERROR: Failed to create data at " + str(addr))
finally:
    currentProgram.endTransaction(tx, True)
"""

    try:
        data = {
            'code': script,
            'language': 'python3'
        }

        response = client.post('script/execute', json_data=data)
        output = formatter.format_simple_result(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)
