"""
Decoding QR codes from high-quality images.

The algorithms in this module are unsophisticated and will
only work for computer generated, non-rotated, undamaged
QR codes. This module can not be used to process QR codes
from photographs or scanned images.

Only Model 2 QR codes are supported.
"""

import sys
import numpy as np
import PIL


# The Reed-Solomon codes for QR error correction are computed over
# the finite field GF(2**8) = GF(2)[a] / (a**8 + a**4 + a**3 + a**2 + 1).
#
# Elements of this field are represented as 8-bit unsigned integers,
# where each bit represents a coefficient of the polynomial with
# the least significant bit corresponding to the lowest order term.
#
# The element "a" (represented as integer value 2) is a primitive element
# of this field.
#
REED_SOLOMON_GF_POLY = 0b100011101


# Construct lookup tables for exp/log:
#   reed_solomon_gf_exp[k] = a**k
#   reed_solomon_gf_log[a**k] = k
reed_solomon_gf_exp = 256 * [0]
reed_solomon_gf_log = 256 * [0]
v = 1
for k in range(1, 256):
    v = (v << 1) ^ ((v >> 7) * REED_SOLOMON_GF_POLY)
    reed_solomon_gf_exp[k] = v
    reed_solomon_gf_log[v] = k
reed_solomon_gf_exp[0] = 1
reed_solomon_gf_log[1] = 0
del k, v


class QRDecodeError(Exception):
    """Raised when QR decoding fails."""
    pass


def debug_msg(msg):
    """Print a debug message."""
    print(msg, file=sys.stderr)


def bits_to_word(bits):
    """Convert a list or array of bits to an integer.

    Parameters:
        bits: List or array of bits, starting with least-significant bit.

    Returns:
        Unsigned integer value of the bits.
    """
    v = 0
    p = 1
    for b in bits:
        if b:
            v += p
        p *= 2
    return v


def decode_version_word(raw_word):
    """Decode error correction bits in the version information.

    Parameters:
        raw_word (int): 18-bit integer containing raw version information.

    Returns:
        6-bit integer containing the decoded QR code version.

    Raises:
        QRDecodeError: If the version information can not be decoded.
    """

    # The version information uses a (18,6) BCH code with generator
    # polynomial x**12 + x**11 + x**10 + x**9 + x**8 + x**5 + x**2 + 1.

    poly = 0b1111100100101

    # This code only detects bit errors but does not correct them.
    # TODO : implement proper error correction

    v = raw_word
    while v >= 2**12:
        if v & 1:
            v ^= poly
        v >>= 1

    if v:
        raise QRDecodeError("Data corruption in version information")

    return raw_word >> 12


def decode_format_word(raw_word):
    """Decode error correction bits in the format word.

    Parameters:
        raw_word (int): 15-bit integer containing raw format information.

    Returns:
        5-bit integer containing the decoded format information.

    Raises:
        QRDecodeError: If the format information can not be decoded.
    """

    # The format word uses a (15,5) BCH code with generator
    # polynomial x**10 + x**8 + x**5 + x**4 + x**2 + x + 1.

    poly = 0b10100110111

    # This code only detects bit errors but does not correct them.
    # TODO : implement proper error correction

    v = raw_word
    while v >= 2**10:
        if v & 1:
            v ^= poly
        v >>= 1

    if v:
        raise QRDecodeError("Data corruption in format bits")

    return raw_word >> 10


def quantize_image(image):
    """Quantize the specified image into black and white pixels.

    Parameters:
        image (PIL.Image): Input image.

    Returns:
        2D Numpy array where 0 = black, 1 = white.
    """

    # Convert to greyscale.
    img_grey = image.convert(mode="L")

    # Extract pixel values.
    data_grey = np.array(img_grey)

    # Quantize to black-and-white.
    min_pixel = np.min(data_grey)
    max_pixel = np.max(data_grey)
    threshold = (min_pixel + max_pixel) // 2
    data_bw = (data_grey > threshold).astype(np.uint8)

    return data_bw


def scan_boundaries(img_data):
    """Scan horizontally to detect color boundaries.

    Returns (boundpos, boundmap).

    boundpos is a 2D array of shape (nrow, ncol+2).
    boundpos[y,k] is the X coordinate of the first pixel after the k-th
      color boundary on row y.
    boundpos[y,0] == 0 by definition.
    boundpos[y,k] == ncol if k is larger than the number of color boundaries.

    boundmap is a 2D array of shape (nrow, ncol).
    boundmap[y,x] is the number of color boundaries to the left of pixel (x,y).
    """

    (nrow, ncol) = img_data.shape

    boundpos = np.zeros((nrow, ncol + 2), dtype=np.uint32)
    boundmap = np.zeros((nrow, ncol), dtype=np.uint32)
    for y in range(nrow):
        (edges,) = np.where(img_data[y, 1:] != img_data[y, :-1])
        boundpos[y, 0] = 0
        if len(edges) > 0:
            boundpos[y, 1:1+len(edges)] = edges + 1
        boundpos[y, 1+len(edges):] = ncol
        steps = np.zeros(ncol)
        steps[edges+1] = 1
        boundmap[y] = np.cumsum(steps)

    return (boundpos, boundmap)


def check_position_detection(bounds):
    """Check whether the specified range of 5 intervals has the right
    proportions to correspond to a slice through a position detection pattern.

    An ideal slice through a position detection pattern consists of
    5 intervals colored B,W,B,W,B with lengths proportional to 1,1,3,1,1.

    Returns:
        (center_coord, pixels_per_module) if this could be a position
        detection pattern, otherwise (0, 0).
    """

    # Expected relative positions of black/white boundaries
    # within the position detection pattern.
    expect_bound_pos = [-3.5, -2.5, -1.5, 1.5, 2.5, 3.5]

    if (len(bounds) != 6) or (bounds[4] >= bounds[5]):
        return (0, 0)

    pattern_width = float(bounds[5] - bounds[0])
    middle_width = float(bounds[3] - bounds[2])
    if (pattern_width < 7) or (middle_width < 3):
        return (0, 0)

    center = float(sum(bounds)) / 6.0
    pitch = (pattern_width + middle_width) / 10.0

    good = True
    for k in range(6):
        rel_bound_pos = (bounds[k] - center) / pitch
        if abs(rel_bound_pos - expect_bound_pos[k]) >= 0.5:
            good = False
            break

    if not good:
        return (0, 0)

    return (center, pitch)


def find_position_detection_patterns(img_data):
    """Locate QR code position detection patterns.

    Parameters:
        img_data (ndarray): 2D Numpy array containing black-and-white image.

    Returns:
        List of tuples (x, y, dx, dy).

    Note that integer values of X/Y coordinates refer to pixel corners.
    The upper-left corner of the image has coordinates (0, 0).
    The center of the upper-left pixel has coordinates (0.5, 0.5).
    The lower-right corner of the image has coordinates (nrow, ncol).
    """

    (nrow, ncol) = img_data.shape

    if (nrow < 7) or (ncol < 7):
        return []

    # Scan for horizontal and vertical color boundaries.
    (hbounds, hmap) = scan_boundaries(img_data)
    (vbounds, vmap) = scan_boundaries(img_data.transpose())

    patterns_raw = []

    # Scan each row to find position detection patterns.
    for y in range(nrow):
        # Start at the first black interval.
        bx = 0
        if img_data[y, 0] != 0:
            bx += 1
        # Consider each range of five intervals with colors B,W,B,W,B.
        while hbounds[y, bx+4] < ncol:
            # Check that this horizontal slice has the correct
            # proportions for a position detection pattern.
            (cx, dx) = check_position_detection(hbounds[y, bx:bx+6])
            if dx > 0:
                # Check that the vertical slice also has a pattern.
                x = int(cx)
                by = vmap[x, y] - 2
                if img_data[y, x] == 0 and by >= 0 and by + 4 < nrow:
                    (cy, dy) = check_position_detection(vbounds[x, by:by+6])
                    if (dy > 0) and (dx <= 2 * dy) and (dy <= 2 * dx):
                        # Add this location as a candidate pattern.
                        patterns_raw.append((cx, cy, dx, dy))
            bx += 2

    # Discard duplicate entries.
    patterns = []
    for fnd in patterns_raw:
        (cx, cy, dx, dy) = fnd
        dupl = False
        for (tcx, tcy, tdx, tdy) in patterns:
            if ((abs(tcx - cx) < 3 * max(dx, tdx))
                    and (abs(tcy - cy) < 3 * max(dy, tdy))):
                dupl = True
                break
        if not dupl:
            patterns.append(fnd)

    return patterns


def make_finder_triplets(patterns):
    """Select three position detection patterns that could
    together form the finder pattern for a QR code.

    If multiple finder triplets are feasible, return them all,
    starting with the highest QR code version.

    Parameters:
        patterns: List of tuples describing position detection patterns.

    Returns:
        List of tuples (finder_ul, finder_ur, finder_dl).
    """

    finder_triplets = []

    # Try all candidates for the upper-left pattern.
    for fnd in patterns:
        (cx, cy, dx, dy) = fnd

        # Search a matching pattern with horizontal separation.
        for fndh in patterns:
            (hcx, hcy, hdx, hdy) = fndh

            # Check that pixel pitch is roughly compatible.
            if 8 * abs(dx - hdx) > dx + hdx:
                continue
            if 8 * abs(dy - hdy) > dy + hdy:
                continue

            # Check that Y coordinates match.
            if abs(cy - hcy) > dy + hdy:
                continue

            # Check that X separation is sufficient.
            xsep = 2 * abs(cx - hcx) / (dx + hdx)
            if xsep < 12:
                continue

            # Search a matching pattern with vertical separation.
            for fndv in patterns:
                (vcx, vcy, vdx, vdy) = fndv

                # Check that pixel pitch is roughly compatible.
                if 8 * abs(dx - vdx) > dx + vdx:
                    continue
                if 8 * abs(dy - vdy) > dy + vdy:
                    continue

                # Check that X coordinates match.
                if abs(cx - vcx) > dx + vdx:
                    continue

                # Check that X and Y separation are roughly compatible.
                ysep = 2 * abs(cy - vcy) / (dy + vdy)
                if ysep < 12 or ysep < 0.75 * xsep or ysep > 1.25 * xsep:
                    continue

                # Identify upper-right and lower-left patterns,
                # depending on rotation.
                if (hcx - cx) * (vcy - cy) > 0:
                    # not rotated or 180 degrees rotated
                    fnd_ur = fndh
                    fnd_dl = fndv
                else:
                    # 90 degrees or 270 degrees rotated
                    fnd_ur = fndv
                    fnd_dl = fndh

                # Estimate QR code version.
                qrver = (0.5 * (xsep + ysep) - 10) / 4.0

                # Bonus point if QR code is non-rotated.
                score = qrver
                if hcx > cx and vcy > cy:
                    score += 1

                finder_triplets.append((score, (fnd, fnd_ur, fnd_dl)))

    # Sort by decreasing score.
    finder_triplets.sort(reverse=True)

    return [triplet for (score, triplet) in finder_triplets]


def extract_qr_version(img_data, finder_ul, finder_ur):
    """Extract the QR version from the upper-right version field.

    Parameters:
        img_data (ndarray): 2D array representing the quantized image.
        finder_ul: Tuple representing the location of the upper-left
            position detection pattern.
        finder_ur: Tuple representing the location of the upper-right
            position detection pattern.

    Returns:
        QR code version (range 1 .. 40).

    Raises:
        QRDecodeError: If the version information can not be decoded.
    """

    (ul_cx, ul_cy, ul_dx, ul_dy) = finder_ul
    (ur_cx, ur_cy, ur_dx, ur_dy) = finder_ur

    # Create affine transform to specify the local QR matrix
    # around the upper-right finder.
    transform = np.zeros((3, 3))
    if abs(ur_cx - ul_cx) > abs(ur_cy - ul_cy):
        # not rotated or 180 degrees rotated
        transform[0, 0] = ur_dx * np.sign(ur_cx - ul_cx)
        transform[1, 1] = ur_dy * np.sign(ur_cx - ul_cx)
    else:
        # 90 degrees or 270 degrees rotated
        transform[1, 0] = ur_dy * np.sign(ur_cy - ul_cy)
        transform[0, 1] = -ur_dx * np.sign(ur_cy - ul_cy)

    transform[0, 2] = ur_cx
    transform[1, 2] = ur_cy
    transform[2, 2] = 1.0

    version_bits = []
    for i in range(18):
        x = i % 3 - 7
        y = i // 3 - 3
        xp = transform[0,0] * x + transform[0,1] * y + transform[0,2]
        yp = transform[1,0] * x + transform[1,1] * y + transform[1,2]
        xp = int(xp)
        yp = int(yp)
        version_bits.append(1 - img_data[yp, xp])

    # Convert bits to word.
    version_word_raw = bits_to_word(version_bits)

    # Decode error correction bits.
    qr_version = decode_version_word(version_word_raw)

    if qr_version < 1 or qr_version > 40:
        raise QRDecodeError("Unsupported QR code version {}"
                            .format(qr_version))

    return qr_version


def locate_qr_code(img_data, triplet):
    """Consider the QR code defined by the specified finder triplet
    and extract precise location, orientation and QR code version.

    Parameters:
        img_data (ndarray): 2D array representing the quantized image.
        triplet: Tuple (finder_ul, finder_ur, finder_dl).

    Returns:
        Tuple (affine_transform, qr_version).

    Raises:
        QRDecodeError: If no QR code was detected.
    """

    (finder_ul, finder_ur, finder_dl) = triplet

    (ul_cx, ul_cy, ul_dx, ul_dy) = finder_ul
    (ur_cx, ur_cy, ur_dx, ur_dy) = finder_ur
    (dl_cx, dl_cy, dl_dx, dl_dy) = finder_dl

    # Estimate the QR code version based on horizontal data.
    hdist = ((2 * (ul_cx - ur_cx) / (ul_dx + ur_dx))**2
             + (2 * (ul_cy - ur_cy) / (ul_dy + ur_dy))**2)**0.5
    qrver = round((hdist - 10) / 4)

    # For QR versions higher than 6, decode the version information.
    if qrver > 6:
        qrver = extract_qr_version(img_data, finder_ul, finder_ur)

    # Determine nominal separation between finders.
    qrsep = 10 + 4 * qrver

    # Determine module-to-pixel scaling and rotation.
    transform = np.zeros((3, 3))
    transform[0, 0] = (ur_cx - ul_cx) / qrsep
    transform[1, 0] = (ur_cy - ul_cy) / qrsep
    transform[0, 1] = (dl_cx - ul_cx) / qrsep
    transform[1, 1] = (dl_cy - ul_cy) / qrsep

    # Determine coordinates of upper-left coordinate.
    transform[0, 2] = ul_cx - 3.5 * (transform[0, 0] + transform[0, 1])
    transform[1, 2] = ul_cy - 3.5 * (transform[1, 0] + transform[1, 1])
    transform[2, 2] = 1.0

    return (transform, qrver)


def sample_qr_matrix(img_data, transform, qr_version):
    """Sample each module in the QR matrix.

    Parameters:
        img_data (ndarray): 2D array representing the quantized image.
        transform (ndarray): Affine transform specifying the position,
            size and orientation of the QR code.
        qr_version (int): QR code version.

    Returns:
        2D square Numpy array containing the value of each module
        (0 = white, 1 = black).
    """

    qrsize = 17 + 4 * qr_version

    xcoord = np.zeros((qrsize, qrsize))
    xcoord[0] = np.arange(qrsize) + 0.5
    xcoord[1:] = xcoord[0]

    ycoord = xcoord.transpose()

    xidx = transform[0,0] * xcoord + transform[0,1] * ycoord + transform[0,2]
    yidx = transform[1,0] * xcoord + transform[1,1] * ycoord + transform[1,2]

    xidx = xidx.astype(np.int32)
    yidx = yidx.astype(np.int32)

    # Clip coordinates to the image area.
    (nrow, ncol) = img_data.shape
    xidx = np.clip(xidx, 0, ncol - 1)
    yidx = np.clip(yidx, 0, nrow - 1)

    matrix = img_data[yidx, xidx]
    matrix = 1 - matrix
    return matrix


def extract_format_data(matrix):
    """Extract format information from the upper-left corner.

    Parameters:
        matrix (ndarray): 2D array containing the QR matrix.

    Returns:
        Tuple (error_correction_level, mask_pattern).

    Raises:
        QRDecodeError: If the format information can not be decoded.
    """

    format_mask = 0b101010000010010

    # Fetch format bits from matrix.
    format_bits = []
    for i in range(6):
        format_bits.append(matrix[i, 8])
    format_bits.append(matrix[7, 8])
    format_bits.append(matrix[8, 8])
    format_bits.append(matrix[8, 7])
    for i in range(6):
        format_bits.append(matrix[8, 5-i])

    # Convert bits to word and apply the format mask.
    format_word_raw = bits_to_word(format_bits)
    format_word_raw ^= format_mask

    # Decode error correction bits.
    format_word = decode_format_word(format_word_raw)

    # Decode error correction level and mask pattern.
    error_correction_idx = ((format_word >> 3) & 3)
    mask_pattern = (format_word & 7)

    error_correction_table = "MLHQ"
    error_correction_level = error_correction_table[error_correction_idx]

    return (error_correction_level, mask_pattern)


def make_mask_pattern(qrsize, mask_pattern):
    """Generate the specified 2D XOR mask pattern.

    Parameters:
        qrsize (int): Size of the QR code (number of modules along one edge).
        mask_pattern (int): Mask pattern reference from format information.

    Returns:
        2D array to be XOR-ed with the matrix before extracting codewords.
    """

    xcoord = np.zeros((qrsize, qrsize), dtype=np.uint32)
    xcoord[0] = np.arange(qrsize)
    xcoord[1:] = xcoord[0]
    ycoord = xcoord.transpose()

    if mask_pattern == 0:
        mask_val = (xcoord + ycoord) % 2
    elif mask_pattern == 1:
        mask_val = ycoord % 2
    elif mask_pattern == 2:
        mask_val = xcoord % 3
    elif mask_pattern == 3:
        mask_val = (xcoord + ycoord) % 3
    elif mask_pattern == 4:
        mask_val = (ycoord // 2 + xcoord // 3) % 2
    elif mask_pattern == 5:
        mask_val = (xcoord * ycoord) % 2 + (xcoord * ycoord) % 3
    elif mask_pattern == 6:
        mask_val = ((xcoord * ycoord) % 2 + (xcoord * ycoord) % 3) % 2
    else:
        mask_val = (xcoord + ycoord + (xcoord * ycoord) % 3) % 2

    mask_bool = (mask_val == 0)
    mask = mask_bool.astype(np.uint8)

    return mask


def get_alignment_pattern_locations(qr_version):
    """Return a list of (x, y) locations of alignment patterns.

    Parameters:
        qr_version (int): QR code version.

    Returns:
        List of tuples (x, y) specifying the center location of
        each alignment pattern.
    """

    coord_tbl = {
        1:  [6],
        2:  [6, 18],
        3:  [6, 22],
        4:  [6, 26],
        5:  [6, 30],
        6:  [6, 34],
        7:  [6, 22, 38],
        8:  [6, 24, 42],
        9:  [6, 26, 46],
        10: [6, 28, 50],
        11: [6, 30, 54],
        12: [6, 32, 58],
        13: [6, 34, 62],
        14: [6, 26, 46, 66],
        15: [6, 26, 48, 70],
        16: [6, 26, 50, 74],
        17: [6, 30, 54, 78],
        18: [6, 30, 56, 82],
        19: [6, 30, 58, 86],
        20: [6, 34, 62, 90],
        21: [6, 28, 50, 72, 94],
        22: [6, 26, 50, 74, 98],
        23: [6, 30, 54, 78, 102],
        24: [6, 28, 54, 80, 106],
        25: [6, 32, 58, 84, 110],
        26: [6, 30, 58, 86, 114],
        27: [6, 34, 62, 90, 118],
        28: [6, 26, 50, 74, 98, 122],
        29: [6, 30, 54, 78, 102, 126],
        30: [6, 26, 52, 78, 104, 130],
        31: [6, 30, 56, 82, 108, 134],
        32: [6, 34, 60, 86, 112, 138],
        33: [6, 30, 58, 86, 114, 142],
        34: [6, 34, 62, 90, 118, 146],
        35: [6, 30, 54, 78, 102, 126, 150],
        36: [6, 24, 50, 76, 102, 128, 154],
        37: [6, 28, 54, 80, 106, 132, 158],
        38: [6, 32, 58, 84, 110, 136, 162],
        39: [6, 26, 54, 82, 110, 138, 166],
        40: [6, 30, 58, 86, 114, 142, 170]
    }

    coords = coord_tbl[qr_version]
    cmin = coords[0]
    cmax = coords[-1]

    align_locs = []
    for y in coords:
        for x in coords:
            if ((x == cmin or y == cmin)
                    and (x in (cmin, cmax))
                    and (y in (cmin, cmax))):
                # Skip alignment patterns that would collide
                # with position detection patterns.
                pass
            else:
                align_locs.append((x, y))

    return align_locs


def get_data_locations(qr_version):
    """Return the locations of all modules representing codewords.

    The locations are sorted in the order of bit placement, starting with
    the most significant bit of the codeword in the lower-right corner.

    Parameters:
        qr_version (int): QR code version.

    Returns:
        Array of shape (num_bits, 2) where each row describes
        a module location with the X coordinate in the first column
        and the Y coordinate in the second column.
    """

    qrsize = 17 + 4 * qr_version

    # Build a map that marks modules used in function patterns.
    func_mask = np.zeros((qrsize, qrsize), dtype=np.uint8)
    func_mask[:9, :9] = 1   # upper-left position detection pattern
    func_mask[:9, -8:] = 1  # upper-right position detection pattern
    func_mask[-8:, :9] = 1  # lower-left position detection pattern
    func_mask[6, :] = 1     # horizontal timing pattern
    func_mask[:, 6] = 1     # vertical timing pattern

    # Mark version information in the mask.
    if qr_version > 6:
        func_mask[:6, -11:-8] = 1   # upper-right version information
        func_mask[-11:-8, :6] = 1   # lower-left version information

    # Mark alignment patterns in the mask.
    align_locs = get_alignment_pattern_locations(qr_version)
    for (x, y) in align_locs:
        func_mask[y-2:y+3, x-2:x+3] = 1

    # List the modules in the QR matrix, including special areas and
    # function patterns but skipping the vertical timing column.
    # List these modules from right to left in strips of two columns wide,
    # alternating between upward and downward traversal of the strips.

    # Number of two-column strips.
    nstrip = (qrsize - 1) // 2

    # Prepare X coordinates.
    xcoords = np.arange(qrsize - 1, 0, -1)  # columns right-to-left
    xcoords[-6:] -= 1                       # skip vertical timing column
    xcoords = xcoords.reshape((nstrip, 2))  # make groups of two columns
    xcoords = np.repeat(xcoords, repeats=qrsize, axis=0)  # repeat for each row
    xcoords = xcoords.flatten()             # ungroup

    # Prepare Y coordinates
    ycoords = np.arange(qrsize)             # list rows downward
    ycoords = np.repeat(ycoords, repeats=2) # repeat for two columns per strip
    ycoords = np.concatenate((ycoords[::-1], ycoords))  # upward + downward
    ycoords = np.tile(ycoords, nstrip // 2) # repeat for each pair of strips

    # Out of this list of modules, select the modules that are not used
    # in function patterns.
    (idx,) = np.nonzero(1 - func_mask[ycoords, xcoords])

    # Build the return array.
    data_locations = np.column_stack((xcoords[idx], ycoords[idx]))
    return data_locations


def extract_codewords(matrix, mask_pattern):
    """Extract the sequence of codewords from the QR matrix.

    Parameters:
        matrix (ndarray):   2D array containing the QR matrix.
        mask_pattern (int): Mask pattern reference from format information.

    Returns:
        Array of codewords in order of placement in the matrix.
    """

    qrsize = matrix.shape[0]
    qr_version = (qrsize - 17) // 4

    # Unmask the QR code.
    mask = make_mask_pattern(qrsize, mask_pattern)
    unmasked_matrix = matrix ^ mask

    # Get the locations of codewords in placement order.
    data_locations = get_data_locations(qr_version)
    xcoords = data_locations[:, 0]
    ycoords = data_locations[:, 1]

    # Fetch codeword bits from the matrix.
    data_bits = unmasked_matrix[ycoords, xcoords]

    # Split bits in groups of 8 bits per codeword.
    nwords = len(data_bits) // 8
    codeword_bits = data_bits[:8*nwords].reshape((nwords, 8))

    # Calculate value of each 8-bit codeword.
    bit_values = (1 << np.arange(8))[::-1]
    codewords = np.sum(codeword_bits * bit_values, axis=1)

    return codewords.astype(np.uint8)


def get_block_structure(qr_version, error_correction_level):
    """Return the data block structure of the specified QR code type.

    Parameters:
        qr_version (int):               QR code version
        error_correction_level (str):   Error correction level (L, M, Q or H).

    Returns:
        Tuple (n_codewords, n_check_words, n_blocks, max_errors).
    """

    num_codewords_table = {
         1:   26,    2:   44,    3:   70,    4:  100,
         5:  134,    6:  172,    7:  196,    8:  242,
         9:  292,   10:  346,   11:  404,   12:  466,
        13:  532,   14:  581,   15:  655,   16:  733,
        17:  815,   18:  901,   19:  991,   20: 1085,
        21: 1156,   22: 1258,   23: 1364,   24: 1474,
        25: 1588,   26: 1706,   27: 1828,   28: 1921,
        29: 2051,   30: 2185,   31: 2323,   32: 2465,
        33: 2611,   34: 2761,   35: 2876,   36: 3034,
        37: 3196,   38: 3362,   39: 3532,   40: 3706
    }

    block_structure_table = {
        1:  [(   7,  1), (  10,  1), (  13,  1), (  17,  1)],
        2:  [(  10,  1), (  16,  1), (  22,  1), (  28,  1)],
        3:  [(  15,  1), (  26,  1), (  36,  2), (  44,  2)],
        4:  [(  20,  1), (  36,  2), (  52,  2), (  64,  4)],
        5:  [(  26,  1), (  48,  2), (  72,  4), (  88,  4)],
        6:  [(  36,  2), (  64,  4), (  96,  4), ( 112,  4)],
        7:  [(  40,  2), (  72,  4), ( 108,  6), ( 130,  5)],
        8:  [(  48,  2), (  88,  4), ( 132,  6), ( 156,  6)],
        9:  [(  60,  2), ( 110,  5), ( 160,  8), ( 192,  8)],
        10: [(  72,  4), ( 130,  5), ( 192,  8), ( 224,  8)],
        11: [(  80,  4), ( 150,  5), ( 224,  8), ( 264, 11)],
        12: [(  96,  4), ( 176,  8), ( 260, 10), ( 308, 11)],
        13: [( 104,  4), ( 198,  9), ( 288, 12), ( 352, 16)],
        14: [( 120,  4), ( 216,  9), ( 320, 16), ( 384, 16)],
        15: [( 132,  6), ( 240, 10), ( 360, 12), ( 432, 18)],
        16: [( 144,  6), ( 280, 10), ( 408, 17), ( 480, 16)],
        17: [( 168,  6), ( 308, 11), ( 448, 16), ( 532, 19)],
        18: [( 180,  6), ( 338, 13), ( 504, 18), ( 588, 21)],
        19: [( 196,  7), ( 364, 14), ( 546, 21), ( 650, 25)],
        20: [( 224,  8), ( 416, 16), ( 600, 20), ( 700, 25)],
        21: [( 224,  8), ( 442, 17), ( 644, 23), ( 750, 25)],
        22: [( 252,  9), ( 476, 17), ( 690, 23), ( 816, 34)],
        23: [( 270,  9), ( 504, 18), ( 750, 25), ( 900, 30)],
        24: [( 300, 10), ( 560, 20), ( 810, 27), ( 960, 32)],
        25: [( 312, 12), ( 588, 21), ( 870, 29), (1050, 35)],
        26: [( 336, 12), ( 644, 23), ( 952, 34), (1110, 37)],
        27: [( 360, 12), ( 700, 25), (1020, 34), (1200, 40)],
        28: [( 390, 13), ( 728, 26), (1050, 35), (1260, 42)],
        29: [( 420, 14), ( 784, 28), (1140, 38), (1350, 45)],
        30: [( 450, 15), ( 812, 29), (1200, 40), (1440, 48)],
        31: [( 480, 16), ( 868, 31), (1290, 43), (1530, 51)],
        32: [( 510, 17), ( 924, 33), (1350, 45), (1620, 54)],
        33: [( 540, 18), ( 980, 35), (1440, 48), (1710, 57)],
        34: [( 570, 19), (1036, 37), (1530, 51), (1800, 60)],
        35: [( 570, 19), (1064, 38), (1590, 53), (1890, 63)],
        36: [( 600, 20), (1120, 40), (1680, 56), (1980, 66)],
        37: [( 630, 21), (1204, 43), (1770, 59), (2100, 70)],
        38: [( 660, 22), (1260, 45), (1860, 62), (2220, 74)],
        39: [( 720, 24), (1316, 47), (1950, 65), (2310, 77)],
        40: [( 750, 25), (1372, 49), (2040, 68), (2430, 81)]
    }

    error_correction_table = {"L": 0, "M": 1, "Q": 2, "H": 3}
    level_code = error_correction_table[error_correction_level]

    n_codewords = num_codewords_table[qr_version]
    (n_check_words, n_blocks) = block_structure_table[qr_version][level_code]

    assert n_check_words % n_blocks == 0
    max_errors = n_check_words // n_blocks // 2
    if max_errors < 6:
        max_errors -= 1

    return (n_codewords, n_check_words, n_blocks, max_errors)


def rs_mul(a, b):
    """Multiply two elements of GF(2**8) as used in the Reed Solomon code.

    Parameters:
        a (int): Integer in range 0 .. 255.
        b (int): Integer in range 0 .. 255.

    Returns:
        Product in GF(2**8) as an integer in range 0 .. 255.
    """

    if a == 0 or b == 0:
        return 0

    # a * b == exp(log(a) + log(b))
    loga = reed_solomon_gf_log[a]
    logb = reed_solomon_gf_log[b]
    result = reed_solomon_gf_exp[(loga + logb) % 255]

    return result


def rs_div(a, b):
    """Divide two elements of GF(2**8) as used in the Reed Solomon code.

    Parameters:
        a (int): Dividend, range 0 .. 255.
        b (int): Divisor, range 1 .. 255.

    Returns:
        Quatient a / b in GF(2**8) as an integer in range 0 .. 255.
    """

    assert b != 0

    if a == 0:
        return 0

    # a / b == exp(log(a) - log(b))
    loga = reed_solomon_gf_log[a]
    logb = reed_solomon_gf_log[b]
    result = reed_solomon_gf_exp[(255 + loga - logb) % 255]

    return result


def rs_eval_poly(poly, x):
    """Evaluate a polynomial within GF(2**8) as used in the Reed Solomon code.

    Parameters:
        poly (ndarray): Array of coefficients of the polynomial,
            starting with the zero-order term.
        x (int): Element to evaluate.

    Returns:
        Value of the polynomial at "x" as an integer.
    """
    n = len(poly) - 1
    ret = poly[n]
    for i in range(n):
        ret = rs_mul(ret, x) ^ poly[n-1-i]
    return ret


def rs_berlekamp_massey(syndrome):
    """Use the Berlekamp-Massey algorithm to calculate
    the error locator polynomial for the specified set of syndromes.

    The error locator polynomial is a polynomial
      C[L] * x**n + C[L-1] * x**(L-1) + ... + C[1] * x + C[0]

    with the following properties:
     - C[0] = 1;
     - the degree "n" is as low as possible;
     - the convolution of C(x) with the syndrome polynomial S(x) equals zero.

    If we view the syndrome as an array S[0], S[1], ... S[N-1],
    the last property of the error locator polynomial can be written
    as follows:
      C[0] * S[k] + C[1] * S[k-1] + ... + C[L] * S[k-L] = 0
      (for all k where L <= k < N).

    All calculations are in the GF(2**8) field of the Reed Solomon code.

    Parameters:
        syndrome (list):        List of syndromes.

    Returns:
        List of coefficients of the error locator polynomial.
    """

    # See https://en.wikipedia.org/wiki/Berlekamp-Massey_algorithm

    n = len(syndrome)
    poly = (n + 1) * [0]
    poly[0] = 1
    prev_poly = list(poly)
    l = 0
    prev_l = 0
    b = 1
    m = 1

    for k in range(n):
        assert prev_l + m == k + 1 - l
        d = syndrome[k]
        for i in range(1, l+1):
            d ^= rs_mul(syndrome[k-i], poly[i])
        if d == 0:
            m += 1
        else:
            ratio = rs_div(d, b)
            if 2 * l <= k:
                for i in range(prev_l, -1, -1):
                    prev_poly[i+m] = poly[i+m]
                    poly[i+m] ^= rs_mul(prev_poly[i], ratio)
                prev_poly[:m] = poly[:m]
                prev_l = l
                l = k + 1 - l
                b = d
                m = 1
            else:
                assert prev_l + m <= l
                for i in range(prev_l + 1):
                    poly[i+m] ^= rs_mul(prev_poly[i], ratio)
                m += 1

    return poly[:l+1]


def rs_forney(syndrome, error_locator, error_locations):
    """Use Forney's algorithm to calculate the error values.

    Parameters:
        syndrome (list):        List of syndromes.
        error_locator (list):   Coefficients of the error locator polynomial.
        error_locations (list): Error locations.

    Returns:
        List with error value for each listed error location.
    """

    # See https://en.wikipedia.org/wiki/Forney_algorithm

    n_error = len(error_locations)
    assert len(error_locator) == n_error + 1
    assert len(syndrome) >= len(error_locator) - 1

    # Calculate the coefficients of the error evaluator polynomial.
    #
    #   err_eval(x) = syndrome(x) * error_locator(x)  (mod x**n_syndrome)
    #
    # Note that the definition of error_locator(x) guarantees that
    # err_eval(x) will have zero-valued coefficients for all terms
    # of degree >= n_error. Thus, the degree of err_eval(x) is at most
    # (n_error - 1), and we only need to calculate the first n_error
    # coefficients.
    #
    err_eval = (len(error_locator) - 1) * [0]
    for k in range(len(error_locator) - 1):
        for i in range(len(error_locator) - k - 1):
            err_eval[k + i] ^= rs_mul(syndrome[k], error_locator[i])

    # Calculate the coefficients of the formal derivative of
    # the error locator polynomial.
    errloc_deriv = (len(error_locator) - 1) * [0]
    for i in range(1, len(error_locator)):
        if i % 2 == 1:
            errloc_deriv[i-1] = error_locator[i]

    # Calculate the error values:
    #   e[k] = X[k] * err_eval(1/X[k]) / errloc_deriv(1/X[k])
    #
    #   where X[k] = a**error_locations[k]
    #
    error_values = n_error * [0]
    for k in range(n_error):
        x = reed_solomon_gf_exp[error_locations[k]]
        xinv = reed_solomon_gf_exp[255-error_locations[k]]
        v_err_eval = rs_eval_poly(err_eval, xinv)
        v_errloc_deriv = rs_eval_poly(errloc_deriv, xinv)
        error_values[k] = rs_div(rs_mul(x, v_err_eval), v_errloc_deriv)

    return error_values


def rs_error_correction(data_words, check_words, max_errors, debug_level=0):
    """Perform Reed-Solomon error correction on a message block.

    Parameters:
        data_words (list):      List of received data words.
        check_words (list):     List of received error correction words.
        max_errors (int):       Maximum number of errors to correct.
        debug_level (int):      Optional debug level.

    Returns:
        List of corrected data words.

    Raises:
        QRDecodeError: If error correction fails.
    """

    n_data_words = len(data_words)
    n_check_words = len(check_words)
    n_received_words = n_data_words + n_check_words
    received_words = data_words + check_words

    # Sanity check on the number of correctable errors.
    assert 2 * max_errors <= n_check_words

    if debug_level >= 2:
        debug_msg("REED-SOLOMON: ({}, {}, r={})"
                  .format(n_received_words, n_data_words, max_errors))

    #
    # See also https://en.wikipedia.org/wiki/Reed-Solomon_error_correction
    #
    # The received words (data words followed by error check words)
    # form a polynomial over GF(2**8):
    #   R(x) = r0 + r1 * x + r2 * x**2 + r3 * x**3 + ...
    #
    # Note that the first received word is the coefficient for the
    # highest-powered term of the polynomial (r0 is the last received word).
    #
    # Calculate the error syndromes for k = 0 .. (n_check_words-1):
    #   syndrome[k] = R(a**k)
    #
    # Note that "a" (represented as integer value 2) is a primitive element
    # of GF(2**8).
    #
    received_poly = received_words[::-1]
    syndrome = n_check_words * [0]
    for k in range(n_check_words):
        x = reed_solomon_gf_exp[k]
        syndrome[k] = rs_eval_poly(received_poly, x)

    # Quick check if all syndromes are zero.
    if all([(x == 0) for x in syndrome]):
        # No errors, just return the data words.
        return data_words

    if debug_level >= 3:
        debug_msg("  syndrome = " + str(syndrome))

    # Determine the error locator polynomial.
    error_locator = rs_berlekamp_massey(syndrome)

    # Check that the degree of the error locator polynomial does not
    # exceed the maximum number of correctable errors.
    n_error = len(error_locator) - 1
    if n_error > max_errors:
        raise QRDecodeError("Uncorrectable errors in Reed-Solomon code")

    if debug_level >= 1:
        debug_msg("REED-SOLOMON: {} errors".format(n_error))

    # Find the roots of the error locator polynomial.
    # If all roots are different AND each root equals "a**(-p[i])" where
    # "p[i]" is a valid index into the received message, then
    # the values "p[i]" represent the error locations.
    error_locations = []
    for k in range(n_received_words):
        x = reed_solomon_gf_exp[255-k]
        v = rs_eval_poly(error_locator, x)
        if v == 0:
            error_locations.append(k)

    if debug_level >= 3:
        debug_msg("  error_locations = " + str(error_locations))

    # Check that all roots of the error locator polynomial are different
    # and correspond to a valid position.
    if len(error_locations) != n_error:
        raise QRDecodeError("Uncorrectable errors in Reed-Solomon code")

    # Use Forney's algorithm to find the error values.
    error_values = rs_forney(syndrome, error_locator, error_locations)

    # Correct errors.
    # Note: location 0 is the last received word.
    for i in range(n_error):
        k = n_received_words - 1 - error_locations[i]
        received_words[k] ^= error_values[i]

    ## Double check that the syndrome is all-zero after error correction.
    ## This check is not necessary; the corrected syndrome is guaranteed
    ## to be zero if Reed-Solomon decoding is correctly implemented.
    ## This is a nice sanity check for debugging.
    #received_poly = received_words[::-1]
    #syndrome = n_check_words * [0]
    #for k in range(n_check_words):
    #    x = reed_solomon_gf_exp[k]
    #    syndrome[k] = rs_eval_poly(received_poly, x)
    #assert all([(x == 0) for x in syndrome])

    # Return the corrected data words.
    return received_words[:n_data_words]


def codeword_error_correction(codewords,
                              qr_version,
                              error_correction_level,
                              debug_level=0):
    """Perform error correction and return only the data codewords.

    Parameters:
        codewords (list):               List of codewords in placement order.
        qr_version (int):               QR code version
        error_correction_level (str):   Error correction level (L, M, Q or H).
        debug_level (int):              Optional debug level.

    Returns:
        List of error-corrected data codewords.

    Raises:
        QRDecodeError: If error correction fails.
    """

    (n_codewords, n_check_words, n_blocks, max_errors
        ) = get_block_structure(qr_version, error_correction_level)

    assert len(codewords) == n_codewords

    n_data_words = n_codewords - n_check_words
    n_data_words_per_block = n_data_words // n_blocks
    n_long_blocks = n_data_words % n_blocks

    corrected_data = []

    for i in range(n_blocks):

        # Collect data words from codeword sequence.
        k = i + n_blocks * n_data_words_per_block
        data_words = codewords[i:k:n_blocks]
        if i >= n_blocks - n_long_blocks:
            extra_word = codewords[n_data_words-n_blocks+i]
            data_words.append(extra_word)

        # Collect error correction words from codeword sequence.
        check_words = codewords[n_data_words+i::n_blocks]

        # Perform Reed-Solomon error correction.
        message = rs_error_correction(data_words,
                                      check_words,
                                      max_errors,
                                      debug_level)
        corrected_data += message

    return corrected_data


def get_bits_from_stream(bitstream, position, num_bits):
    """Read bits from the bitstream.

    Parameters:
        bitstream (list):       List of 8-bit data codewords.
        position (int):         Index of first bit to read.
        num_bits (int):         Number of bits to read.

    Returns:
        Integer representing the obtained bits (most-significant bit first).

    Raises:
        QRDecodeError: If the requested range exceeds the bitstream length.
    """

    if position + num_bits > 8 * len(bitstream):
        raise QRDecodeError("Unexpected end of bitstream")

    word_pos = position // 8
    bit_pos = position % 8

    k = min(num_bits, 8 - bit_pos)
    mask = (1 << k) - 1
    value = (bitstream[word_pos] >> (8 - bit_pos - k)) & mask

    bits_remaining = num_bits - k

    while bits_remaining >= 8:
        word_pos += 1
        word = bitstream[word_pos]
        value = (value << 8) | word
        bits_remaining -= 8

    if bits_remaining > 0:
        word_pos += 1
        mask = (1 << bits_remaining) - 1
        lsb = 8 - bits_remaining
        word = (bitstream[word_pos] >> (8 - bits_remaining)) & mask
        value = (value << bits_remaining) | word

    return value


def decode_numeric_segment(bitstream, position, nchar):
    """Decode a segment in numeric mode.

    Parameters:
        bitstream (ndarray):    Array of 8-bit data codewords.
        position (int):         Bit position within the bitstream.
        nchar (int):            Number of characters to decode.

    Returns:
        Tuple (decoded_data, new_position).

    Raises:
        QRDecodeError: If decoding fails or end of bitstream is reached.
    """
    frag = bytearray(nchar)
    ndone = 0
    while ndone < nchar:
        k = min(nchar - ndone, 3)
        nbits = 3 * k + 1
        value = get_bits_from_stream(bitstream, position, nbits)
        position += nbits
        if k > 2:
            frag[ndone+2] = 0x30 + value % 10
            value = value // 10
        if k > 1:
            frag[ndone+1] = 0x30 + value % 10
            value = value // 10
        if value > 9:
            raise QRDecodeError("Invalid numeric data")
        frag[ndone] = 0x30 + value
        ndone += k
    return (frag, position)


def decode_alphanumeric_segment(bitstream, position, nchar):
    """Decode a segment in alphanumeric mode.

    Parameters:
        bitstream (ndarray):    Array of 8-bit data codewords.
        position (int):         Bit position within the bitstream.
        nchar (int):            Number of characters to decode.

    Returns:
        Tuple (decoded_data, new_position).

    Raises:
        QRDecodeError: If decoding fails or end of bitstream is reached.
    """
    alphanum_table = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
    assert len(alphanum_table) == 45
    frag = bytearray(nchar)
    ndone = 0
    while ndone < nchar:
        k = min(nchar - ndone, 2)
        nbits = 5 * k + 1
        value = get_bits_from_stream(bitstream, position, nbits)
        position += nbits
        if k > 1:
            frag[ndone+1] = alphanum_table[value % 45]
            value = value // 45
        if value > 44:
            raise QRDecodeError("Invalid alphanumeric data")
        frag[ndone] = alphanum_table[value]
        ndone += k
    return (frag, position)


def decode_8bit_segment(bitstream, position, nchar):
    """Decode a segment in 8-bit mode.

    Parameters:
        bitstream (ndarray):    Array of 8-bit data codewords.
        position (int):         Bit position within the bitstream.
        nchar (int):            Number of characters to decode.

    Returns:
        Tuple (decoded_data, new_position).

    Raises:
        QRDecodeError: If decoding fails or end of bitstream is reached.
    """
    frag = bytearray(nchar)
    for i in range(nchar):
        frag[i] = get_bits_from_stream(bitstream, position, 8)
        position += 8
    return (frag, position)


def decode_bitstream(bitstream, qr_version):
    """Decode the specified QR bitstream.

    Parameters:
        bitstream (list):       Array of 8-bit data codewords.
        qr_version (int):       QR code version.

    Returns:
        Decoded data as a bytestring.

    Raises:
        QRDecodeError: If decoding fails.
    """

    # Determine number of bits in character count field.
    if qr_version <= 9:
        character_count_bits = [0, 10, 9, 0, 8]
    elif qr_version <= 26:
        character_count_bits = [0, 12, 11, 0, 16]
    else:
        character_count_bits = [0, 14, 13, 0, 16]

    decoded_data = bytearray()
    position = 0

    # Decode segments until end of bitstream (or terminator).
    while position + 4 <= 8 * len(bitstream):

        # Read mode indicator.
        mode = get_bits_from_stream(bitstream, position, 4)
        position += 4

        # Stop at terminator marker.
        if mode == 0:
            break

        # Reject unsupported modes.
        if mode not in (1, 2, 4):
            if mode == 7:
                raise QRDecodeError("ECI mode not supported")
            if mode == 3:
                raise QRDecodeError("Structured Append mode not supported")
            if mode in (5, 9):
                raise QRDecodeError("FNC1 mode not supported")
            if mode == 8:
                raise QRDecodeError("Kanji mode not supported")
            raise QRDecodeError("Unsupported mode indicator 0x{:x}"
                                .format(mode))

        # Read character count.
        nbits = character_count_bits[mode]
        nchar = get_bits_from_stream(bitstream, position, nbits)
        if nchar < 0:
            raise QRDecodeError("Unexpected end of bitstream")
        position += nbits

        # Decode characters.
        if mode == 1:
            (frag, position
                ) = decode_numeric_segment(bitstream, position, nchar)
        elif mode == 2:
            (frag, position
                ) = decode_alphanumeric_segment(bitstream, position, nchar)
        elif mode == 4:
            (frag, position
                ) = decode_8bit_segment(bitstream, position, nchar)

        decoded_data += frag

    return bytes(decoded_data)


def matrix_to_string(matrix):
    """Format the QR matrix as a string."""

    lines = []
    qrsize = matrix.shape[0]
    for y in range(qrsize):
        s = []
        for x in range(qrsize):
            if matrix[y, x] == 0:
                s.append(".")
            elif matrix[y, x] == 1:
                s.append("X")
            else:
                s.append("?")
        lines.append("  " + " ".join(s))
    return "\n".join(lines)


def bitstream_to_string(bitstream):
    """Format the bitstream as a string."""
    bits = []
    for word in bitstream:
        for k in range(8):
            bits.append((word >> (7 - k)) & 1)
    return "".join(map(str, bits))


def decode_qrcode(image, debug_level=0):
    """Decode the QR code in the specified image.

    Parameters:
        image (PIL.Image): Input image.
        debug_level (int): Optional debug level (0..3).

    Returns:
        Decoded data as a byte string.

    Raises:
        QRDecodeError: If decoding fails.
    """

    # Convert to black-and-white.
    img_data = quantize_image(image)

    # Locate position detection patterns.
    patterns = find_position_detection_patterns(img_data)

    if debug_level >= 2:
        debug_msg("POSITION DETECTION PATTERNS:")
        for pattern in patterns:
            debug_msg("  " + str(pattern))

    if len(patterns) < 3:
        npattern = len(patterns)
        if npattern == 0:
            raise QRDecodeError("No position detection patterns found")
        raise QRDecodeError("Only {} position detection patterns found"
                            .format(npattern))

    # Make groups of three compatible finders.
    finder_triplets = make_finder_triplets(patterns)

    if len(finder_triplets) == 0:
        raise QRDecodeError("No valid finder pattern found")

    # Try to decode according to each triplet.
    first_exception = None
    for triplet in finder_triplets:

        if debug_level >= 1:
            debug_msg("FINDER TRIPLET:")
            for fnd in triplet:
                debug_msg("  " + str(fnd))

        try:
            # Extract QR code location, orientation and version.
            transform, qr_version = locate_qr_code(img_data, triplet)

            if debug_level >= 2:
                debug_msg("AFFINE TRANSFORM:")
                debug_msg(str(transform))

            # Sample the QR matrix.
            matrix = sample_qr_matrix(img_data, transform, qr_version)

            if debug_level >= 3:
                debug_msg(matrix_to_string(matrix))

            # Extract format information.
            (error_correction_level, mask_pattern
                ) = extract_format_data(matrix)

            if debug_level >= 1:
                debug_msg("QR VERSION: {} {} mask={}"
                          .format(qr_version,
                                  error_correction_level,
                                  mask_pattern))

            # Extract codewords from the QR matrix.
            codewords = extract_codewords(matrix, mask_pattern)

            # Unpack codeword sequence and perform error correction.
            bitstream = codeword_error_correction(list(codewords),
                                                  qr_version,
                                                  error_correction_level,
                                                  debug_level)

            if debug_level >= 3:
                debug_msg("BITSTREAM: " + bitstream_to_string(bitstream))

        except QRDecodeError as exc:
            # If decoding fails on the first finder triplet,
            # save the exception and try decoding the remaining triplets.
            # If all triplets fail, report the error from the first triplet.
            if first_exception is None:
                first_exception = exc
            if debug_level >= 1:
                debug_msg("FAILED: " + str(exc))
            continue

        # Successfully extracted a bitstream from the QR code.
        # This implies we correctly located the QR code in the image,
        # so from this point on it does not make sense to retry with
        # different finder triplets if an error occurs.

        # Decode the bitstream.
        return decode_bitstream(bitstream, qr_version)

    raise first_exception

