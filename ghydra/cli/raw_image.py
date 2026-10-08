"""Raw image definition and cleanup commands."""

import click

from ..client.exceptions import GhidraError
from ..utils import should_page, page_output, rich_echo, validate_address


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

    try:
        response = client.post('raw-image/define', json_data={
            'address': validate_address(address),
            'width': width,
            'height': height,
            'format': pixel_format,
            'endian': endian,
        })
        output = formatter.format_simple_result(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@raw_image.command('cleanup')
@click.option('--address', '-a', help='Address of the raw image to clear (hex)')
@click.option('--all', 'clear_all', is_flag=True, default=False,
              help='Clear every RawImage data item in the program')
@click.pass_context
def cleanup(ctx, address, clear_all):
    """Remove RawImage data items created by 'raw-image define'.

    Clears the RawImage at the given address, or every RawImage in the program with
    --all. Clearing a code unit leaves the underlying bytes undefined again.

    Idempotent: cleaning up when nothing is defined reports removed=0 rather than
    failing. Collection and clearing run in a single transaction, so a failure
    part-way through a whole-program sweep rolls back everything.

    \b
    Examples:
        ghydra raw-image cleanup --address 0x401000
        ghydra raw-image cleanup --all
        ghydra --json raw-image cleanup --all
    """
    if not clear_all and not address:
        rich_echo("[red]Error:[/red] Provide --address, or --all to sweep the whole program", err=True)
        ctx.exit(1)

    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    payload = {'all': True} if clear_all else {'address': validate_address(address)}

    try:
        response = client.post('raw-image/cleanup', json_data=payload)
        output = formatter.format_simple_result(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)
