import pefile
import numpy as np
import pandas as pd

def preprocess(df):
    for i in range(len(df)):
        file_path = str(df.loc[i, "Name"])
        try:
            pe = pefile.PE(file_path)
        except:
            continue
        df.loc[i, "e_magic"] = pe.DOS_HEADER.e_magic
        df.loc[i, "e_cblp"] = pe.DOS_HEADER.e_cblp
        df.loc[i, "e_cp"] = pe.DOS_HEADER.e_cp
        df.loc[i, "e_crlc"] = pe.DOS_HEADER.e_crlc
        df.loc[i, "e_cparhdr"] = pe.DOS_HEADER.e_cparhdr
        df.loc[i, "e_minalloc"] = pe.DOS_HEADER.e_minalloc
        df.loc[i, "e_maxalloc"] = pe.DOS_HEADER.e_maxalloc
        df.loc[i, "e_ss"] = pe.DOS_HEADER.e_ss
        df.loc[i, "e_sp"] = pe.DOS_HEADER.e_sp
        df.loc[i, "e_csum"] = pe.DOS_HEADER.e_csum
        df.loc[i, "e_ip"] = pe.DOS_HEADER.e_ip
        df.loc[i, "e_cs"] = pe.DOS_HEADER.e_cs
        df.loc[i, "e_lfarlc"] = pe.DOS_HEADER.e_lfarlc
        df.loc[i, "e_ovno"] = pe.DOS_HEADER.e_ovno
        df.loc[i, "e_oemid"] = pe.DOS_HEADER.e_oemid
        df.loc[i, "e_oeminfo"] = pe.DOS_HEADER.e_oeminfo
        df.loc[i, "e_lfanew"] = pe.DOS_HEADER.e_lfanew
        df.loc[i, "Machine"] = pe.FILE_HEADER.Machine
        df.loc[i, "NumberOfSections"] = pe.FILE_HEADER.NumberOfSections
        df.loc[i, "TimeDateStamp"] = pe.FILE_HEADER.TimeDateStamp
        df.loc[i, "PointerToSymbolTable"] = pe.FILE_HEADER.PointerToSymbolTable
        df.loc[i, "NumberOfSymbols"] = pe.FILE_HEADER.NumberOfSymbols
        df.loc[i, "SizeOfOptionalHeader"] = pe.FILE_HEADER.SizeOfOptionalHeader
        df.loc[i, "Characteristics"] = pe.FILE_HEADER.Characteristics
        df.loc[i, "Magic"] = pe.OPTIONAL_HEADER.Magic
        df.loc[i, "MajorLinkerVersion"] = pe.OPTIONAL_HEADER.MajorLinkerVersion
        df.loc[i, "MinorLinkerVersion"] = pe.OPTIONAL_HEADER.MinorLinkerVersion
        df.loc[i, "SizeOfCode"] = pe.OPTIONAL_HEADER.SizeOfCode
        df.loc[i, "SizeOfInitializedData"] = pe.OPTIONAL_HEADER.SizeOfInitializedData
        df.loc[i, "SizeOfUninitializedData"] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
        df.loc[i, "AddressOfEntryPoint"] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        df.loc[i, "BaseOfCode"] = pe.OPTIONAL_HEADER.BaseOfCode
        df.loc[i, "ImageBase"] = pe.OPTIONAL_HEADER.ImageBase
        df.loc[i, "SectionAlignment"] = pe.OPTIONAL_HEADER.SectionAlignment
        df.loc[i, "FileAlignment"] = pe.OPTIONAL_HEADER.FileAlignment
        df.loc[i, "MajorOperatingSystemVersion"] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        df.loc[i, "MinorOperatingSystemVersion"] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
        df.loc[i, "MajorImageVersion"] = pe.OPTIONAL_HEADER.MajorImageVersion
        df.loc[i, "MinorImageVersion"] = pe.OPTIONAL_HEADER.MinorImageVersion
        df.loc[i, "MajorSubsystemVersion"] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
        df.loc[i, "MinorSubsystemVersion"] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
        df.loc[i, "SizeOfHeaders"] = pe.OPTIONAL_HEADER.SizeOfHeaders
        df.loc[i, "CheckSum"] = pe.OPTIONAL_HEADER.CheckSum
        df.loc[i, "SizeOfImage"] = pe.OPTIONAL_HEADER.SizeOfImage
        df.loc[i, "Subsystem"] = pe.OPTIONAL_HEADER.Subsystem
        df.loc[i, "DllCharacteristics"] = pe.OPTIONAL_HEADER.DllCharacteristics
        df.loc[i, "SizeOfStackReserve"] = pe.OPTIONAL_HEADER.SizeOfStackReserve
        df.loc[i, "SizeOfStackCommit"] = pe.OPTIONAL_HEADER.SizeOfStackCommit
        df.loc[i, "SizeOfHeapReserve"] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
        df.loc[i, "SizeOfHeapCommit"] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
        df.loc[i, "LoaderFlags"] = pe.OPTIONAL_HEADER.LoaderFlags
        df.loc[i, "NumberOfRvaAndSizes"] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
        df.loc[i, "SectionsLength"] = len(pe.sections)
        
        section_entropy_dict = {}
        for section in pe.sections:
            section_name = section.Name.decode('utf-8').strip('\x00')
            entropy = section.get_entropy()
            section_entropy_dict[section_name] = entropy
            
        df.loc[i, "SectionMinEntropy"] = min(section_entropy_dict.values())
        df.loc[i, "SectionMaxEntropy"] = max(section_entropy_dict.values())
        
        section_raw_size_dict = {}
        for section in pe.sections:
            section_name = section.Name.decode('utf-8').strip('\x00')
            raw_size = section.SizeOfRawData
            section_raw_size_dict[section_name] = raw_size

        df.loc[i, "SectionMinRawsize"] = min(section_raw_size_dict.values())
        df.loc[i, "SectionMaxRawsize"] = max(section_raw_size_dict.values())
        
        section_virt_size_dict = {}
        for section in pe.sections:
            section_name = section.Name.decode('utf-8').strip('\x00')
            virt_size = section.Misc_VirtualSize
            section_virt_size_dict[section_name] = virt_size
            
        df.loc[i, "SectionMinVirtualsize"] = min(section_virt_size_dict.values())
        df.loc[i, "SectionMaxVirtualsize"] = max(section_virt_size_dict.values())
        
        section_physical_addr_dict = {}
        for section in pe.sections:
            section_name = section.Name.decode('utf-8').strip('\x00')
            physical = section.Misc_PhysicalAddress
            section_physical_addr_dict[section_name] = physical
            
        df.loc[i, "SectionMaxPhysical"] = max(section_physical_addr_dict.values())
        df.loc[i, "SectionMinPhysical"] = min(section_physical_addr_dict.values())
        
        section_virt_addr_dict = {}
        for section in pe.sections:
            section_name = section.Name.decode('utf-8').strip('\x00')
            virtual = section.VirtualAddress
            section_virt_addr_dict[section_name] = virtual
    
        df.loc[i, "SectionMaxVirtual"] = max(section_virt_addr_dict.values())
        df.loc[i, "SectionMinVirtual"] = min(section_virt_addr_dict.values())
        
        section_pointer_data_dict = {}
        for section in pe.sections:
            section_name = section.Name.decode('utf-8').strip('\x00')
            pointer_data = section.PointerToRawData
            section_pointer_data_dict[section_name] = pointer_data
            
        df.loc[i, "SectionMaxPointerData"] = max(section_pointer_data_dict.values())
        df.loc[i, "SectionMinPointerData"] = min(section_pointer_data_dict.values())

        section_char_dict = {}
        for section in pe.sections:
            section_name = section.Name.decode('utf-8').strip('\x00')
            chars = section.Characteristics
            section_char_dict[section_name] = chars
            
        df.loc[i, "SectionMaxChar"] = max(section_char_dict.values())
        df.loc[i, "SectionMainChar"] = min(section_char_dict.values())
        
        try:
            df.loc[i, "DirectoryEntryImport"] = len(pe.DIRECTORY_ENTRY_IMPORT)
        except:
            df.loc[i, "DirectoryEntryImport"] = 0
        try:
            df.loc[i, "DirectoryEntryExport"] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        except:
            df.loc[i, "DirectoryEntryExport"] = 0
        
        df.loc[i, "ImageDirectoryEntryExport"] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']].Size
        df.loc[i, "ImageDirectoryEntryImport"] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].Size
        df.loc[i, "ImageDirectoryEntryResource"] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']].Size
        df.loc[i, "ImageDirectoryEntryException"] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXCEPTION']].Size
        df.loc[i, "ImageDirectoryEntrySecurity"] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size
    return df