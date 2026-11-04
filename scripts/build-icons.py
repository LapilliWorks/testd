#!/usr/bin/env python3
"""Generate the Tauri bundle and tray icons from the canonical assets.

Sources live in assets/brand/:
  testd-app.png            1024px fat app icon
  testd-tray-mask.png      alpha mask for the tray frame and `.t`
  testd-tray-plate-mask.png alpha mask for the plate knockout

Writes src-tauri/icons/ without third-party dependencies.
"""

import os
import struct

import png

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.join(HERE, '..')
ASSETS = os.path.join(REPO, 'assets', 'brand')
ICONS = os.path.join(REPO, 'src-tauri', 'icons')

SQUARE_LOGOS = (30, 44, 71, 89, 107, 142, 150, 284, 310)
TRAY_COLOR = (0, 0, 0)
TRAY_DARK = (255, 255, 255)
TRAY_ALERT = (215, 0, 21)
TRAY_REQUEST = (96, 165, 250)
PLATE_COLOR = (255, 255, 255)

_app_source: tuple[int, bytes] | None = None


def load_app_source() -> tuple[int, bytes]:
	global _app_source
	if _app_source is None:
		path = os.path.join(ASSETS, 'testd-app.png')
		width, height, data = png.read_rgba(path)
		if width != height:
			raise ValueError(f'{path}: expected a square icon, got {width}x{height}')
		_app_source = (width, data)
	return _app_source


def app_rgba(size: int) -> bytes:
	source_size, data = load_app_source()
	return png.resize_rgba(data, source_size, source_size, size, size)


def write_ico(path: str, sizes: tuple[int, ...], source) -> None:
	entries = []
	for size in sizes:
		data = source(size)
		blob = png.encode_rgba(size, size, data) if size >= 256 else ico_entry_bmp(size, data)
		entries.append((size, blob))
	out = struct.pack('<HHH', 0, 1, len(entries))
	offset = 6 + 16 * len(entries)
	body = b''
	for size, blob in entries:
		dim = 0 if size >= 256 else size
		out += struct.pack('<BBBBHHII', dim, dim, 0, 0, 1, 32, len(blob), offset)
		offset += len(blob)
		body += blob
	with open(path, 'wb') as fh:
		fh.write(out + body)


def ico_entry_bmp(size: int, data: bytes) -> bytes:
	"""32-bit BGRA DIB entry and 1bpp AND mask, as stored by .ico."""
	header = struct.pack('<IiiHHIIiiII', 40, size, size * 2, 1, 32, 0, 0, 0, 0, 0, 0)
	rows = []
	for y in range(size - 1, -1, -1):
		row = bytearray()
		for x in range(size):
			i = (y * size + x) * 4
			row += bytes((data[i + 2], data[i + 1], data[i], data[i + 3]))
		rows.append(bytes(row))
	mask_row = bytes(((size + 31) // 32) * 4)
	return header + b''.join(rows) + mask_row * size


def write_icns(path: str, source) -> None:
	# type -> pixel size; PNG payloads, accepted by macOS since 10.7.
	types = [(b'icp4', 16), (b'icp5', 32), (b'icp6', 64), (b'ic07', 128), (b'ic08', 256),
			 (b'ic09', 512), (b'ic10', 1024), (b'ic11', 32), (b'ic12', 64), (b'ic13', 256),
			 (b'ic14', 512)]
	body = b''
	for tag, size in types:
		blob = png.encode_rgba(size, size, source(size))
		body += tag + struct.pack('>I', len(blob) + 8) + blob
	with open(path, 'wb') as fh:
		fh.write(b'icns' + struct.pack('>I', len(body) + 8) + body)


def write_app_set() -> None:
	cache: dict[int, bytes] = {}

	def source(size: int) -> bytes:
		if size not in cache:
			cache[size] = app_rgba(size)
		return cache[size]

	for size, name in ((16, '16x16.png'), (32, '32x32.png'), (64, '64x64.png'),
					   (128, '128x128.png'), (256, '128x128@2x.png'), (512, 'icon.png'),
					   (1024, 'icon-1024.png')):
		png.write_rgba(os.path.join(ICONS, name), size, size, source(size))

	write_icns(os.path.join(ICONS, 'icon.icns'), source)
	write_ico(os.path.join(ICONS, 'icon.ico'), (16, 24, 32, 48, 64, 128, 256), source)

	for size in SQUARE_LOGOS:
		png.write_rgba(os.path.join(ICONS, f'Square{size}x{size}Logo.png'), size, size, source(size))
	png.write_rgba(os.path.join(ICONS, 'StoreLogo.png'), 50, 50, source(50))


def load_mask(name: str) -> bytes:
	path = os.path.join(ASSETS, name)
	width, height, data = png.read_rgba(path)
	if width != 32 or height != 32:
		raise ValueError(f'{path}: expected a 32x32 mask, got {width}x{height}')
	return data


def colorize(mask: bytes, color: tuple[int, int, int]) -> bytes:
	out = bytearray(len(mask))
	for i in range(0, len(mask), 4):
		out[i:i + 3] = bytes(color)
		out[i + 3] = mask[i + 3]
	return bytes(out)


def write_tray() -> None:
	tray = load_mask('testd-tray-mask.png')
	plate = load_mask('testd-tray-plate-mask.png')

	for name, color, mask in (
		('tray-on-light.png', TRAY_COLOR, tray),
		('tray-on-dark.png', TRAY_DARK, tray),
		('tray-on-light-alert.png', TRAY_ALERT, tray),
		('tray-on-light-request.png', TRAY_REQUEST, tray),
		('tray-plate.png', PLATE_COLOR, plate),
		('tray-plate-alert.png', TRAY_ALERT, plate),
		('tray-plate-request.png', TRAY_REQUEST, plate),
	):
		png.write_rgba(os.path.join(ICONS, name), 32, 32, colorize(mask, color))


def main() -> None:
	os.makedirs(ICONS, exist_ok=True)
	write_app_set()
	write_tray()
	print('wrote', ICONS)


if __name__ == '__main__':
	main()
