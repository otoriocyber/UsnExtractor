import argparse

# consts
STANDARD_INFORMATION = b'\x10\x00\x00\x00'
ATTRIBUTE_LIST = b'\x20\x00\x00\x00'
FILE_NAME = b'\x30\x00\x00\x00'
OBJECT_ID = b'\x40\x00\x00\x00'
SECURITY_DESCRIPTOR = b'\x50\x00\x00\x00'
VOLUME_NAME = b'\x60\x00\x00\x00'
VOLUME_INFORMATION = b'\x70\x00\x00\x00'
DATA = b'\x80\x00\x00\x00'
INDEX_ROOT = b'\x90\x00\x00\x00'
INDEX_ALLOCATION = b'\xA0\x00\x00\x00'
BITMAP = b'\xB0\x00\x00\x00'
REPARSE_POINT = b'\xC0\x00\x00\x00'
EA_INFORMATION = b'\xD0\x00\x00\x00'
EA = b'\xE0\x00\x00\x00'
PROPERTY_SET = b'\xF0\x00\x00\x00'
LOGGED_UTILITY_STREAM = b'\x00\x01\x00\x00'
ATTRIBUTE_END_MARKER = b'\xFF\xFF\xFF\xFF'


class DataRun:
    def __init__(self, header, length, offset):
        self.header = header
        self.length = length
        self.offset = offset


class RawOffset:
    def __init__(self, offset, bytes_acc, bytes_per_run, sectors_per_run):
        self.offset = offset
        self.bytes_acc = bytes_acc
        self.bytes_per_run = bytes_per_run
        self.sectors_per_run = sectors_per_run


class BootSector:
    def __init__(self, buffer):
        self.align = buffer[0]
        self.jump = buffer[0:3]
        self.SystemName = buffer[3:11]
        self.BytesPerSector = int.from_bytes(buffer[11:13], byteorder="little")
        self.sectors_per_cluster = int.from_bytes(buffer[13:14], byteorder="little")
        self.ReservedSectors = int.from_bytes(buffer[14:16], byteorder="little")
        self.MediaDescriptor = int.from_bytes(buffer[21:22], byteorder="little")
        self.SectorsPerTrack = int.from_bytes(buffer[24:26], byteorder="little")
        self.NumberOfHeads = int.from_bytes(buffer[26:28], byteorder="little")
        self.HiddenSectors = int.from_bytes(buffer[28:32], byteorder="little")
        self.TotalSectors = int.from_bytes(buffer[40:48], byteorder="little")
        self.LogicalClusterNumberforthefileMFT = int.from_bytes(buffer[48:56], byteorder="little")
        self.LogicalClusterNumberforthefileMFTMirr = int.from_bytes(buffer[56:64], byteorder="little")
        self.ClustersPerFileRecordSegment = int.from_bytes(buffer[64:68], byteorder="little")
        self.ClustersPerIndexBlock = int.from_bytes(buffer[68:72], byteorder="little")
        self.NTFSVolumeSerialNumber = int.from_bytes(buffer[72:80], byteorder="little")
        self.Checksum = int.from_bytes(buffer[80:82], byteorder="little")


class NtfsAttributes:
    def __init__(self):
        self.standard_information = None
        self.attribute_list = None
        self.file_name = None
        self.object_id = None
        self.security_descriptor = None
        self.volume_name = None
        self.volume_information = None
        self.data = None
        self.index_root = None
        self.index_allocation = None
        self.bitmap = None
        self.reparse_point = None
        self.ea_information = None
        self.ea = None
        self.property_set = None
        self.logged_utility_stream = None
        self.attribute_end_marker = None


class Indx:
    def __init__(self):
        self.indx_entry_number = None
        self.indx_mft_ref = None
        self.indx_file_name = None


def swap(data):
    return "".join([data[i: i + 2] for i in range(0, len(data), 2)][::-1])


def extract_boot_sector(handle):
    data = handle.read(512)
    boot_sector = BootSector(data)
    bytes_per_cluster = boot_sector.BytesPerSector * boot_sector.sectors_per_cluster
    mft_offset = bytes_per_cluster * boot_sector.LogicalClusterNumberforthefileMFT
    if boot_sector.ClustersPerFileRecordSegment > 127:
        mft_record_size = 2 ** (256 - boot_sector.ClustersPerFileRecordSegment)
    else:
        mft_record_size = bytes_per_cluster * boot_sector.ClustersPerFileRecordSegment

    return bytes_per_cluster, mft_offset, mft_record_size, boot_sector.sectors_per_cluster


def get_last_offset(runs):
    if runs:
        counter = 0
        while counter < len(runs) and int(runs[-counter].offset, 16) == 0:
            counter += 1
        if runs[-counter].offset != 0:
            return runs[-counter].offset
        else:
            return "0"
    else:
        return "0"


def parse_data_run(data_run):
    i = 0
    runs = []
    r = 0
    base = 0
    data_run = "".join(['0x{0:0{1}X}'.format(ord(data_run[i:i + 1]), 2)[2:] for i in range(len(data_run))])
    while i < len(data_run):
        header = data_run[i:i + 2]
        if header != "00":
            length = swap(data_run[i + 2:i + 2 + int(header[1], 16) * 2])
            if not length:
                length = "0"
            length = "0x{}".format(length)
            offset_string = swap(
                data_run[i + 2 + int(header[1], 16) * 2:i + 2 + int(header[1], 16) * 2 + int(header[0], 16) * 2])
            if offset_string:
                add_to_offset = int(offset_string, 16) - ((r > 1) and int(offset_string[0], 16) > 7) * int(
                    "10000000000000000"[:int(header[0], 16) * 2 + 1], 16)
                base += add_to_offset
                offset = hex(base)

                offset_data = offset if offset else "0x0"
            else:
                offset_data = "0x0"
            if int(length, 16) > 16 and int(length, 16) % 16 > 0:
                runs.append(DataRun(header, int(length, 16) - int(length, 16) % 16, int(offset_data, 16)))
                offset_data = hex(int(offset_data, 16) + runs[-1].length)
                length = hex(int(length, 16) % 16)
            runs.append(DataRun(header, int(length, 16), int(offset_data, 16)))
        else:
            break
        i = i + 2 + int(header[1], 16) * 2 + int(header[0], 16) * 2
        r += 1
    return runs


def get_raw_offset(handle, parsed, real_size, bytes_per_cluster, raw_entry=None):
    header_name = ""

    if raw_entry:
        header_relative_len = int.from_bytes(raw_entry[9:10], "little")
        header_relative_offset = int.from_bytes(raw_entry[10:12], byteorder="little")
        if header_relative_len > 0:
            header_name = "".join([chr(i) for i in raw_entry[
                                                   header_relative_offset: header_relative_offset + header_relative_len * 2].replace(
                b"\x00", b"")])

    raw_offsets = []
    bytes_acc = 0
    core_attribute = b""
    for run in parsed:
        # sparse data - offset unknown
        if run.offset == 0:
            offset = 0
            bytes_acc = bytes_per_cluster * run.length
            real_size -= bytes_per_cluster * run.length
            raw_offsets.append(RawOffset(offset, bytes_acc, 0, 0))
            bytes_acc = 0
            continue

        # else - normal data
        offset = run.offset * bytes_per_cluster
        handle.seek(offset)
        g = run.length  # cluster len
        while g > 16 and real_size > bytes_per_cluster * 16:
            bytes_acc += bytes_per_cluster * 16
            data = handle.read(bytes_per_cluster * 16)
            core_attribute += data[:bytes_per_cluster * 16]
            g -= 16
            real_size -= bytes_per_cluster * 16

        if g != 0:  # add leftovers
            data = handle.read(bytes_per_cluster * 16)
            if real_size > bytes_per_cluster * g:
                core_attribute += data[:bytes_per_cluster * g]
                bytes_acc += bytes_per_cluster * g
                real_size -= bytes_per_cluster * g
            else:
                core_attribute += data[:real_size]
                bytes_acc += real_size

        if raw_offsets:
            if raw_offsets[-1].offset == 0:
                raw_offsets.append(RawOffset(offset, bytes_acc, bytes_acc, bytes_acc / 512))
            else:
                bytes_per_run = bytes_acc - raw_offsets[-1].bytes_acc
                raw_offsets.append(RawOffset(offset, bytes_acc, bytes_per_run, bytes_per_run / 512))

    return raw_offsets, core_attribute, header_name


def get_attributes(entry):
    nfts_attributes = NtfsAttributes()
    attribute_offset = int.from_bytes(entry[20:21], byteorder="little")
    while True:
        attribute_type = entry[attribute_offset:attribute_offset + 4]
        attribute_size = int.from_bytes(entry[attribute_offset + 4:attribute_offset + 8], byteorder="little")
        if attribute_type == ATTRIBUTE_LIST:
            nfts_attributes.attribute_list = entry[attribute_offset:attribute_offset + attribute_size]
        elif attribute_type == FILE_NAME:
            nfts_attributes.file_name = entry[attribute_offset:attribute_offset + attribute_size]
        elif attribute_type == DATA:
            if not nfts_attributes.data:
                nfts_attributes.data = entry[attribute_offset:attribute_offset + attribute_size]
        elif attribute_type == INDEX_ROOT:
            nfts_attributes.index_root = entry[attribute_offset:attribute_offset + attribute_size]
        elif attribute_type == INDEX_ALLOCATION:
            nfts_attributes.index_allocation = entry[attribute_offset:attribute_offset + attribute_size]
        elif attribute_type == ATTRIBUTE_END_MARKER:
            break
        attribute_offset += attribute_size

    return nfts_attributes


def parse_mft_record(mft_entry):
    attribute_offset = int(hex(ord(mft_entry[20:21])), 16)
    attribute_type = 0
    while attribute_type < 256:
        attribute_type = int.from_bytes(mft_entry[attribute_offset:attribute_offset + 4], byteorder="little")
        attribute_size = int.from_bytes(mft_entry[attribute_offset + 4: attribute_offset + 8], byteorder="little")
        if attribute_type == 128:
            datarun = decode_attribute(mft_entry[attribute_offset:attribute_offset + attribute_size])
            return datarun
        else:
            attribute_offset += attribute_size


def decode_index_entries(data_run):
    entries = []
    next_entry_offset = 0
    while next_entry_offset + 16 < len(data_run):
        index = Indx()
        mft_ref = int.from_bytes(data_run[next_entry_offset:next_entry_offset + 6], byteorder="little")
        index.indx_mft_ref = mft_ref
        flags = int.from_bytes(data_run[next_entry_offset + 11: next_entry_offset + 13], byteorder="little")

        indx_filename_length = int.from_bytes(data_run[next_entry_offset + 80:next_entry_offset + 81],
                                              byteorder="little")
        data = data_run[next_entry_offset + 82: next_entry_offset + 82 + indx_filename_length * 2]
        index_filename = "".join([chr(i) for i in data.replace(b"\x00", b"")])
        index.indx_file_name = index_filename

        padding = (2 + indx_filename_length * 2) % 8
        if padding:
            padding = 8 - padding

        if flags:
            sub_node_offset_length = 8
        else:
            sub_node_offset_length = 0
        index.indx_entry_number = 0
        entries.append(index)

        next_entry_offset += 82 + indx_filename_length * 2 + padding + sub_node_offset_length

    return entries


def get_ref(name, indx_entries):
    for entry in indx_entries:
        if entry.indx_file_name == name:
            return entry.indx_mft_ref


def get_index_entries(entry):
    index_entry = entry[32:]
    return decode_index_entries(index_entry)


def strip_mft_record(record):
    record = update_record(record)
    record_size = int.from_bytes(record[24:28], byteorder="little")
    header_size = int.from_bytes(record[20:22], byteorder="little")
    return record[header_size:record_size - 8]


def strip_index(index):
    record_size = int.from_bytes(index[28:30], byteorder="little")
    header_size = int.from_bytes(index[24:28], byteorder="little")
    is_not_leaf_node = index[36:37]
    entry = index[24 + header_size:24 + header_size + record_size - header_size - 16]
    if is_not_leaf_node == b"\x01":
        entry = entry[:-16]

    return entry


# Get the INDX entries from the entry
def get_index_alloc_entries(entry):
    next_position = 0
    total_indx_entries = b""
    while next_position < len(entry) + 32:
        header = "".join([chr(i) for i in entry[next_position: next_position + 4]])
        if header != "INDX":
            next_position += 4096
            continue
        indx_entries = strip_index(entry[next_position: next_position + 4096])
        total_indx_entries += indx_entries
        next_position += 4096

    return decode_index_entries(total_indx_entries)


# processes data attribute
def decode_attribute(attr):
    resident = attr[8]
    if resident:
        offset = int.from_bytes(attr[32:34], byteorder="little")
        datarun = attr[offset:]
    else:
        offset = int.from_bytes(attr[20:22], byteorder="little")
        datarun = attr[offset:]

    return datarun


# find the mft record of a file in the mft
def find_file_MFT_record(handle, target_file, parsed_data_run, mft_record_size, sectors_per_cluster, bytes_per_cluster):
    counter = 0
    final = 0
    jump = 0
    records_divisor = mft_record_size / 512
    records_in_run = -1
    run = None
    for run in parsed_data_run:
        records_in_run = run.length * sectors_per_cluster / records_divisor
        counter += records_in_run
        if counter > target_file:
            break

    if records_in_run < 0 or not run:
        return

    # the offset of the record where usn in \\.\c
    base = counter - records_in_run
    records_per_cluster = sectors_per_cluster / records_divisor

    while final < target_file:
        jump += records_per_cluster
        final = base + jump

    # records over the usn
    records_too_much = final - target_file
    location = run.offset * bytes_per_cluster + jump / records_per_cluster * bytes_per_cluster - records_too_much * mft_record_size
    handle.seek(int(location))
    record = handle.read(mft_record_size)

    if int.from_bytes(record[44:48], byteorder="little") == target_file:
        return location, record
    else:
        return


def get_core_attribute(handle, record, real_size, parsed_datarun, index, bytes_per_cluster):
    entries = []
    result = get_raw_offset(handle, parsed_datarun, real_size, bytes_per_cluster, record)
    if result:
        raw, core_attribute, header_name = result
        if header_name == "$I30":
            if index == INDEX_ROOT:
                entries = get_index_entries(core_attribute)
            elif index == INDEX_ALLOCATION:
                entries = get_index_alloc_entries(core_attribute)

    return entries


def update_record(record):
    offset = int.from_bytes(record[4:6], byteorder="little")
    size = int.from_bytes(record[6:8], byteorder="little")
    data = record[offset: offset + size * 2]

    return record[0:510] + data[2:4] + record[512:1022] + data[4:6]


# resolve the path to the mft reference
def resolve(handle, path, data_run, mft_record_size, sectors_per_cluster, bytes_per_cluster):
    resolved = None
    next_ref = 5
    splitted = path.split("\\")
    if len(splitted) > 2:
        for i in range(len(splitted[2:])):
            part = splitted[i + 1]
            result = find_file_MFT_record(handle, next_ref, data_run, mft_record_size, sectors_per_cluster,
                                          bytes_per_cluster)
            if not result:
                print("parsing error")
                exit(0)
            location, record = result
            record = update_record(record)

            ntfs_attributes = get_attributes(record)
            record_data_run = decode_attribute(ntfs_attributes.index_allocation)
            parsed_data_run = parse_data_run(record_data_run)

            record_size = int.from_bytes(ntfs_attributes.index_allocation[48:48 + 8], "little")

            indx_entries = get_core_attribute(handle, ntfs_attributes.index_allocation, record_size, parsed_data_run,
                                              INDEX_ALLOCATION, bytes_per_cluster)

            next_ref = get_ref(part, indx_entries)
            if i == len(splitted[2:]) - 1:
                result = find_file_MFT_record(handle, next_ref, data_run, mft_record_size, sectors_per_cluster,
                                              bytes_per_cluster)
                if result:
                    location, record = result
                    record = update_record(record)
                    ntfs_attributes = get_attributes(record)
                    indx_entries = get_index_entries(ntfs_attributes.index_root[32:])

                resolved = get_ref(splitted[-1], indx_entries)

    return resolved


def get_refs(attr_list, current_ref):
    refs = []
    offset = 0
    while len(attr_list) > offset:
        ref = int.from_bytes(attr_list[offset + 16:offset + 20], byteorder="little")
        if ref != current_ref:
            refs.append(ref)
        offset += int.from_bytes(attr_list[offset + 4: offset + 6], byteorder="little")

    return refs


def get_total_clusters(entry):
    start_offset = int.from_bytes(entry[16:24], byteorder="little")
    last_offset = int.from_bytes(entry[24:32], byteorder="little")
    total_clusters = last_offset - start_offset
    return total_clusters


def parse_attribute_list(attribute_list, usn_ref, handle, mft_data_run, mft_record_size, sectors_per_cluster,
                         bytes_per_cluster):
    raw_offsets = []
    list_offset = int.from_bytes(attribute_list[20:22], byteorder="little")
    a_list = attribute_list[list_offset:]
    refs = get_refs(a_list, usn_ref)
    prev_size = 0
    prev_total_clusters = 0
    for tmp_ref in refs:
        result = find_file_MFT_record(handle, tmp_ref, mft_data_run, mft_record_size, sectors_per_cluster,
                                      bytes_per_cluster)
        if not result:
            print("Something went wrong")
            continue
        location, record = result
        attr = strip_mft_record(record)
        offset = int.from_bytes(attr[32:34], byteorder="little")
        record_data_run = attr[offset:]
        attr_size = int.from_bytes(attr[48:48 + 8], byteorder="little")
        total_clusters = get_total_clusters(attr)
        if not attr_size:
            total_clusters = prev_total_clusters
            attr_size = prev_size - total_clusters * bytes_per_cluster
        prev_size = attr_size
        prev_total_clusters = total_clusters
        parsed = parse_data_run(record_data_run)
        raw_offsets, core_attribute, header_name = get_raw_offset(handle, parsed, attr_size, bytes_per_cluster, attr)

    return raw_offsets


def parse_attribute_data(handle, data, bytes_per_cluster):
    offset = int.from_bytes(data[32:34], byteorder="little")
    record_data_run = data[offset:]

    usn_size = int.from_bytes(data[48:48 + 8], byteorder="little")

    parsed = parse_data_run(record_data_run)
    raw_offsets, core_attribute, header_name = get_raw_offset(handle, parsed, usn_size, bytes_per_cluster)

    return raw_offsets


def dump_to_file(handle, raw_offsets, dest):
    with open(dest, "wb") as output:
        for raw_offset in raw_offsets[1:]:
            handle.seek(raw_offset.offset)
            data = handle.read(raw_offset.bytes_per_run)
            written = output.write(data)


def main():
    print("""
##################################
Windows UsnJrnl Extractor
Created by OTORIO - www.otorio.com
##################################
""")

    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--output", help="Output path", default="./usn.bin")
    args = parser.parse_args()

    output_path = args.output
    target_file = r"C:\$Extend\$UsnJrnl"

    print("[+] Getting handle to physical partition")
    try:
        handle = open(r"\\.\c:", "rb")
    except:
        print("[!] Failed to get handle to the physical partition, are you running with administrative privileges?")
        exit(0)

    print("[+] Parsing boot sector")
    # Get data about the filesystem from the boot sector
    bytes_per_cluster, mft_offset, mft_record_size, sectors_per_cluster = extract_boot_sector(handle)

    print("[+] Getting mft record in the mft")
    # Find the mft record of the mft
    handle.seek(mft_offset)
    mft_record = handle.read(mft_record_size)
    if mft_record[22:24] != b"\x01\x00" or int.from_bytes(mft_record[44:48], byteorder='little', signed=False) != 0:
        print("Couldn't find the MFT record")
        exit(0)

    print("[+] Finding the reference to the usnjrnl")
    mft_data_run_data = parse_mft_record(mft_record)
    mft_data_run = parse_data_run(mft_data_run_data)
    ref = resolve(handle, target_file, mft_data_run, mft_record_size, sectors_per_cluster, bytes_per_cluster)

    print("[+] Finding usnjrnl record")
    offset, record = find_file_MFT_record(handle, ref, mft_data_run, mft_record_size, sectors_per_cluster,
                                          bytes_per_cluster)
    record = update_record(record)

    print("[+] Finding raw offsets on disk")
    ntfs_attributes = get_attributes(record)
    if ntfs_attributes.attribute_list:
        raw_offsets = parse_attribute_list(ntfs_attributes.attribute_list, ref, handle, mft_data_run, mft_record_size,
                                           sectors_per_cluster, bytes_per_cluster)
    else:
        raw_offsets = parse_attribute_data(handle, ntfs_attributes.data, bytes_per_cluster)

    print("[+] Reading data from raw offsets")
    dump_to_file(handle, raw_offsets, output_path)

    print("Extracted usn to - {}".format(output_path))


if __name__ == "__main__":
    main()
