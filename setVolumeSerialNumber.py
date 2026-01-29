import os
import argparse
from abc import ABC, abstractmethod

SECTOR_SIZE = 0x200


# ============================================================
#  BinaryView: typed integer access + simple compare method
# ============================================================

class BinaryView:
    """Wraps a byte buffer and provides typed little-endian integer access."""

    def __init__(self, buffer: bytearray):
        self.buf = buffer

    def u16_le(self, offset: int) -> int:
        return int.from_bytes(self.buf[offset:offset + 2], "little")

    def u32_le(self, offset: int) -> int:
        return int.from_bytes(self.buf[offset:offset + 4], "little")

    def u64_le(self, offset: int) -> int:
        return int.from_bytes(self.buf[offset:offset + 8], "little")

    def set_u16_le(self, offset: int, value: int):
        self.buf[offset:offset + 2] = (value & 0xFFFF).to_bytes(2, "little")

    def set_u32_le(self, offset: int, value: int):
        self.buf[offset:offset + 4] = (value & 0xFFFFFFFF).to_bytes(4, "little")

    def set_u64_le(self, offset: int, value: int):
        self.buf[offset:offset + 8] = (value & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")

    def compare_bytes(self, pattern: bytes, offset: int) -> bool:
        """Compare pattern against buffer starting at offset."""
        length = len(pattern)
        return self.buf[offset:offset + length] == pattern


# ============================================================
#  RawDevice: low-level sector I/O (lazy-open + context manager)
# ============================================================

class RawDevice:
    """Provides raw sector-level read/write access to a Windows volume.
    Lazily opens the device handle only when first accessed.
    """

    def __init__(self, drive_letter: str):
        self.drive = drive_letter.upper().replace(":", "")
        self.path = fr"\\.\{self.drive}:"
        self._handle = None  # lazy-open
        
    def __del__(self):
        self.close()
        
    @property
    def handle(self):
        if self._handle is None:
            self._handle = os.open( self.path, os.O_RDWR | os.O_BINARY )
        return self._handle

    def close(self):
        if self._handle is not None:
            os.close(self._handle)
            self._handle = None

    # with block
    def __enter__(self):
        return self

    # with block
    def __exit__(self, exc_type, exc, tb):
        self.close()


    def read_sector(self, offset: int = 0) -> BinaryView:
        os.lseek(self.handle, offset, os.SEEK_SET)
        data = os.read(self.handle, SECTOR_SIZE)
        if len(data) != SECTOR_SIZE:
            raise IOError("Sector could not be read completely")
        return BinaryView(bytearray(data))

    def write_sector(self, offset: int, data: bytes | bytearray):
        if len(data) != SECTOR_SIZE:
            raise IOError(f"Sector must be exactly {SECTOR_SIZE} bytes")
        os.lseek(self.handle, offset, os.SEEK_SET)
        os.write(self.handle, data)


# ============================================================
#  Mixins for formatting
# ============================================================

class FatStyleFormatterMixin:
    def format_fat32_style(self, serial32: int) -> str:
        s = f"{serial32:08X}"
        return f"{s[:4]}-{s[4:]}"


class Ntfs64FormatterMixin:
    def format_ntfs64_style(self, serial64: int) -> str:
        s = f"{serial64:016X}"
        return f"{s[:8]}-{s[8:]}"


# ============================================================
#  Abstract Volume
# ============================================================

class Volume(ABC):
    """Abstract representation of a filesystem volume."""

    SIGNATURE: bytes = None
    SIGNATURE_OFFSET: int = None
    SERIAL_OFFSET: int = None

    def __init__(self, device: RawDevice):
        self.device = device
        self.boot = self._load_bootsector()

    def _load_bootsector(self) -> BinaryView:
        view = self.device.read_sector(0)
        if view.buf[0] != 0xEB:
            raise IOError("Boot sector must start with opcode 0xEB")
        return view

    def matches(self) -> bool:
        if self.SIGNATURE is None or self.SIGNATURE_OFFSET is None:
            raise NotImplementedError("Volume subclass must define SIGNATURE and SIGNATURE_OFFSET")
        return self.boot.compare_bytes(self.SIGNATURE, self.SIGNATURE_OFFSET)

    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @abstractmethod
    def read_serial(self) -> int:
        ...

    @abstractmethod
    def write_serial(self, new_serial: int):
        ...

    @abstractmethod
    def format_serial(self, serial: int) -> str:
        ...

    def apply_serial(self, new_serial: int):
        self.write_serial(new_serial)
        self.device.write_sector(0, self.boot.buf)


# ============================================================
#  NTFS Volume
# ============================================================

class NTFSVolume(Volume, Ntfs64FormatterMixin):
    SIGNATURE = b"NTFS "
    SIGNATURE_OFFSET = 3
    SERIAL_OFFSET = 0x48

    @property
    def name(self) -> str:
        return "NTFS"

    def read_serial(self) -> int:
        return self.boot.u64_le(self.SERIAL_OFFSET)

    def write_serial(self, new_serial: int):
        self.boot.set_u64_le(self.SERIAL_OFFSET, new_serial)

    def format_serial(self, serial: int) -> str:
        return self.format_ntfs64_style(serial)


# ============================================================
#  FAT32 Volume
# ============================================================

class FAT32Volume(Volume, FatStyleFormatterMixin):
    
    SIGNATURE = b"FAT32"
    SIGNATURE_OFFSET = 0x52
    
    SERIAL_OFFSET    = 0x43

    @property
    def name(self) -> str:
        return "FAT32"

    def read_serial(self) -> int:
        return self.boot.u32_le(self.SERIAL_OFFSET)

    def write_serial(self, new_serial: int):
        self.boot.set_u32_le(self.SERIAL_OFFSET, new_serial)

    def format_serial(self, serial: int) -> str:
        return self.format_fat32_style(serial)


# ============================================================
#  FAT16/12 Volume
# ============================================================

class FAT16Volume(Volume, FatStyleFormatterMixin):
    
    SIGNATURE = b"FAT"
    SIGNATURE_OFFSET = 0x36
    
    SERIAL_OFFSET    = 0x27

    @property
    def name(self) -> str:
        return "FAT12/16"

    def read_serial(self) -> int:
        return self.boot.u32_le(self.SERIAL_OFFSET)

    def write_serial(self, new_serial: int):
        self.boot.set_u32_le(self.SERIAL_OFFSET, new_serial)

    def format_serial(self, serial: int) -> str:
        return self.format_fat32_style(serial)


# ============================================================
#  VolumeFactory (pythonic)
# ============================================================

class VolumeFactory:
    VOLUME_TYPES = (
        NTFSVolume,
        FAT32Volume,
        FAT16Volume,
    )


    @staticmethod
    def open(drive_letter: str) -> Volume:
        device = RawDevice(drive_letter)

        for volume_cls in VolumeFactory.VOLUME_TYPES:
            vol = volume_cls(device)
            if vol.matches():
                return vol

        raise ValueError("Unknown or unsupported filesystem")


# ============================================================
#  VolumeInspector
# ============================================================

class VolumeInspector:
    def __init__(self, drive_letter: str):
        self.volume = VolumeFactory.open(drive_letter)

    def show_info(self):
        vol = self.volume
        print(f"Volume {vol.device.drive}: filesystem = {vol.name}")
        
        serial = vol.read_serial()
        print(f"Raw value:    {serial:X}")
        print(f"Formatted:    {vol.format_serial(serial)}")

        if isinstance(vol, NTFSVolume):
            low32 = serial & 0xFFFFFFFF
            print(  f"NTFS Low32:   {low32:08X} ("
                    f"{FatStyleFormatterMixin().format_fat32_style(low32)}"
                    f")" 
            )

    def apply_new_serial(self, low_str: str, high_str: str | None):
        vol = self.volume

        # Low-Teil immer parsen
        low = parse_serial_string(low_str)
        new_serial =   low 



        
        # NTFS: High-Teil nur ändern, wenn explizit angegeben
        if isinstance(vol, NTFSVolume):
            if high_str is None:
                # High bleibt unverändert
                high = (vol.read_serial() >> 32) & 0xFFFFFFFF
                print("Note: High part of NTFS serial remains unchanged.")
                print("      Provide a value like 0000-0000 to modify it.")
            else:
                high = parse_serial_string(high_str)

            new_serial = (high << 32) | low 

        print("\nWriting new serial:")
        print(f"  {vol.format_serial(new_serial)}")

        vol.apply_serial(new_serial)
        vol.device.close()



# ============================================================
#  CLI helpers
# ============================================================
def validate_drive(text: str) -> str:
    d = text.upper().replace(":", "")
    if len(d) != 1 or not d.isalpha():
        raise argparse.ArgumentTypeError(
            f"Invalid drive '{text}'. Expected something like C: or D"
        )
    return d + ":"


def parse_serial_string(text: str) -> int:
    cleaned = text.replace("-", "").strip()
    return int(cleaned, 16) & 0xFFFFFFFF


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Volume serial inspector/editor")
    p.add_argument("drive", type=validate_drive,
                    help="Drive letter, e.g. C: or C")
                    
    p.add_argument("low_serial", nargs="?",   
                    help="Low part of serial (hex)")
                    
    p.add_argument("high_serial", nargs="?", 
                    help="High part (NTFS only)")
    return p


# ============================================================
#  main()
# ============================================================

def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    inspector = VolumeInspector(args.drive)

    # Wenn keine Serial angegeben wurde → nur anzeigen
    if args.low_serial is None:
        inspector.show_info()
        return

    # Sonst: Serial setzen
    inspector.show_info()
    inspector.apply_new_serial(args.low_serial, args.high_serial)



if __name__ == "__main__":
    main()
