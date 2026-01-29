# setVolumeSerialNumber

A small, focused utility for **reading and modifying the volume serial number** of FAT and NTFS file systems on Windows.

Windows exposes the serial number through the built‑in `vol` command, but it provides **no official API** to change it.  
PowerShell, WMI, Win32 APIs, and even modern storage management layers intentionally leave a gap here - likely because some licensing and DRM systems rely on the serial number as a “unique” identifier.

This tool fills that gap in a transparent, open, and well-structured way.

---

## Why this tool exists

Microsoft’s own Sysinternals tool  
**[volumeid](https://learn.microsoft.com/en-us/sysinternals/downloads/volumeid)**  
can modify the serial number, but it is closed‑source and not extensible.

setVolumeSerialNumber is
- **A practical example of clean Python architecture**
- **A demonstration of class design, lazy initialization, properties, and factory patterns**

---

## Usage examples:

- Administrator privileges are required.

```
setVolumeSerialNumber C:
```
Shows the current serial number

```
setVolumeSerialNumber C: 1122-3344
```
Sets only the low 32 bits (NTFS high part remains unchanged):

```
setVolumeSerialNumber C: 1122-3344 AABB-CCDD
```
Set both high and low parts (NTFS only):


---

## Technical details

- Direct raw access to `\\.\C:` using Python  
- Filesystem detection via signature offsets:
  - NTFS: `"NTFS "` at offset 3  
  - FAT32: `"FAT32"` at offset 82  
  - FAT16: `"FAT"` at offset 54  
- Serial number offsets:
  - NTFS: `0x48`
  - FAT32: `0x43`
  - FAT16: `0x27`
- Clean separation of responsibilities:
  - `RawDevice` for low‑level access  
  - `BinaryView` for typed byte operations  
  - `Volume` subclasses for NTFS/FAT parsing  
  - `VolumeFactory` for filesystem detection  

---
