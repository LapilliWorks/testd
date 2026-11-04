"""Minimal 8-bit RGBA PNG I/O and area resampling, without third-party deps."""

import struct
import zlib


def read_rgba(path: str) -> tuple[int, int, bytes]:
	"""Read a non-interlaced 8-bit RGBA PNG into packed RGBA rows."""
	with open(path, 'rb') as fh:
		data = fh.read()

	pos, idat = 8, b''
	width = height = 0
	while pos < len(data):
		length = struct.unpack('>I', data[pos:pos + 4])[0]
		tag = data[pos + 4:pos + 8]
		body = data[pos + 8:pos + 8 + length]
		if tag == b'IHDR':
			width, height, depth, color, _, _, interlace = struct.unpack('>IIBBBBB', body)
			if depth != 8 or color != 6 or interlace != 0:
				raise ValueError(f'{path}: expected a non-interlaced 8-bit RGBA PNG')
		elif tag == b'IDAT':
			idat += body
		pos += 12 + length

	raw = zlib.decompress(idat)
	stride = width * 4
	rows = []
	previous = bytearray(stride)
	pos = 0
	for _ in range(height):
		filter = raw[pos]
		line = bytearray(raw[pos + 1:pos + 1 + stride])
		pos += 1 + stride
		if filter == 1:
			for i in range(4, stride):
				line[i] = (line[i] + line[i - 4]) & 255
		elif filter == 2:
			for i in range(stride):
				line[i] = (line[i] + previous[i]) & 255
		elif filter == 3:
			for i in range(stride):
				left = line[i - 4] if i >= 4 else 0
				line[i] = (line[i] + ((left + previous[i]) >> 1)) & 255
		elif filter == 4:
			for i in range(stride):
				left = line[i - 4] if i >= 4 else 0
				up = previous[i]
				up_left = previous[i - 4] if i >= 4 else 0
				estimate = left + up - up_left
				da, db, dc = abs(estimate - left), abs(estimate - up), abs(estimate - up_left)
				nearest = left if (da <= db and da <= dc) else (up if db <= dc else up_left)
				line[i] = (line[i] + nearest) & 255
		elif filter != 0:
			raise ValueError(f'{path}: unsupported PNG filter {filter}')
		rows.append(bytes(line))
		previous = line
	return width, height, b''.join(rows)


def encode_rgba(width: int, height: int, data: bytes) -> bytes:
	"""Encode packed RGBA rows as a PNG file."""
	def chunk(tag: bytes, body: bytes) -> bytes:
		return (struct.pack('>I', len(body)) + tag + body
				+ struct.pack('>I', zlib.crc32(tag + body) & 0xffffffff))

	raw = bytearray()
	row_bytes = width * 4
	for y in range(height):
		raw.append(0)
		raw += data[y * row_bytes:(y + 1) * row_bytes]
	return (b'\x89PNG\r\n\x1a\n'
			+ chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0))
			+ chunk(b'IDAT', zlib.compress(bytes(raw), 9))
			+ chunk(b'IEND', b''))


def write_rgba(path: str, width: int, height: int, data: bytes) -> None:
	with open(path, 'wb') as fh:
		fh.write(encode_rgba(width, height, data))


def resize_rgba(data: bytes, source_width: int, source_height: int,
				width: int, height: int) -> bytes:
	"""Area-average packed RGBA rows, premultiplying alpha while sampling."""
	if source_width == width and source_height == height:
		return data

	scale_x = source_width / width
	scale_y = source_height / height
	out = bytearray(width * height * 4)
	for y in range(height):
		y0 = y * scale_y
		y1 = (y + 1) * scale_y
		y_start = int(y0)
		y_end = min(source_height, int(y1) + 1)
		for x in range(width):
			x0 = x * scale_x
			x1 = (x + 1) * scale_x
			x_start = int(x0)
			x_end = min(source_width, int(x1) + 1)
			red = green = blue = alpha = total = 0.0
			for source_y in range(y_start, y_end):
				weight_y = min(y1, source_y + 1) - max(y0, source_y)
				if weight_y <= 0:
					continue
				row = source_y * source_width
				for source_x in range(x_start, x_end):
					weight_x = min(x1, source_x + 1) - max(x0, source_x)
					if weight_x <= 0:
						continue
					weight = weight_x * weight_y
					offset = (row + source_x) * 4
					source_alpha = data[offset + 3]
					red += data[offset] * source_alpha * weight
					green += data[offset + 1] * source_alpha * weight
					blue += data[offset + 2] * source_alpha * weight
					alpha += source_alpha * weight
					total += weight
			offset = (y * width + x) * 4
			if alpha > 0:
				out[offset] = round(red / alpha)
				out[offset + 1] = round(green / alpha)
				out[offset + 2] = round(blue / alpha)
			out[offset + 3] = round(alpha / total)
	return bytes(out)
