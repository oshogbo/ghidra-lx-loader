package lx;import java.io.IOException;


import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;

/*   
 * [Doc]
           +-----+-----+-----+-----+-----+-----+-----+-----+
       00h | "L"   "X" |B-ORD|W-ORD|     FORMAT LEVEL      |
           +-----+-----+-----+-----+-----+-----+-----+-----+
       08h | CPU TYPE  |  OS TYPE  |    MODULE VERSION     |
           +-----+-----+-----+-----+-----+-----+-----+-----+
       10h |     MODULE FLAGS      |   MODULE # OF PAGES   |
           +-----+-----+-----+-----+-----+-----+-----+-----+
       18h |     EIP OBJECT #      |          EIP          |
           +-----+-----+-----+-----+-----+-----+-----+-----+
       20h |     ESP OBJECT #      |          ESP          |
           +-----+-----+-----+-----+-----+-----+-----+-----+
       28h |       PAGE SIZE       |   PAGE OFFSET SHIFT   |
           +-----+-----+-----+-----+-----+-----+-----+-----+
       30h |  FIXUP SECTION SIZE   | FIXUP SECTION CHECKSUM|
           +-----+-----+-----+-----+-----+-----+-----+-----+
       38h |  LOADER SECTION SIZE  |LOADER SECTION CHECKSUM|
           +-----+-----+-----+-----+-----+-----+-----+-----+
       40h |    OBJECT TABLE OFF   |  # OBJECTS IN MODULE  |
           +-----+-----+-----+-----+-----+-----+-----+-----+
       48h | OBJECT PAGE TABLE OFF | OBJECT ITER PAGES OFF |
           +-----+-----+-----+-----+-----+-----+-----+-----+
       50h | RESOURCE TABLE OFFSET |#RESOURCE TABLE ENTRIES|
           +-----+-----+-----+-----+-----+-----+-----+-----+
       58h | RESIDENT NAME TBL OFF |   ENTRY TABLE OFFSET  |
           +-----+-----+-----+-----+-----+-----+-----+-----+
       60h | MODULE DIRECTIVES OFF | # MODULE DIRECTIVES   |
           +-----+-----+-----+-----+-----+-----+-----+-----+
       68h | FIXUP PAGE TABLE OFF  |FIXUP RECORD TABLE OFF |
           +-----+-----+-----+-----+-----+-----+-----+-----+
       70h | IMPORT MODULE TBL OFF | # IMPORT MOD ENTRIES  |
           +-----+-----+-----+-----+-----+-----+-----+-----+
       78h |  IMPORT PROC TBL OFF  | PER-PAGE CHECKSUM OFF |
           +-----+-----+-----+-----+-----+-----+-----+-----+
       80h |   DATA PAGES OFFSET   |    #PRELOAD PAGES     |
           +-----+-----+-----+-----+-----+-----+-----+-----+
       88h | NON-RES NAME TBL OFF  | NON-RES NAME TBL LEN  |
           +-----+-----+-----+-----+-----+-----+-----+-----+
       90h | NON-RES NAME TBL CKSM |   AUTO DS OBJECT #    |
           +-----+-----+-----+-----+-----+-----+-----+-----+
       98h |    DEBUG INFO OFF     |    DEBUG INFO LEN     |
           +-----+-----+-----+-----+-----+-----+-----+-----+
       A0h |   #INSTANCE PRELOAD   |   #INSTANCE DEMAND    |
           +-----+-----+-----+-----+-----+-----+-----+-----+
       A8h |       HEAPSIZE        |
           +-----+-----+-----+-----+
*/

public class LXHeader implements StructConverter {
	public String signature;			 	/* 00h */	
	public byte b_ord;						/* 02h */
	public byte w_ord;          			/* 03h */
	public long	format_level;				/* 04h */
	public int	cpu_type;					/* 08h */
	public int	os_type;					/* 0Ah */
	public long	module_version; 			/* 0Ch */
	public long module_flag;				/* 10h */
	public long	module_of_pages;			/* 14h */
	public long eip_object;					/* 18h */
	public long eip;						/* 1Ch */
	public long esp_object;					/* 20h */
	public long esp;						/* 24h */
	public long	page_size;					/* 28h */
	/* 
	 * ? bytes on the last page?
	 * http://faydoc.tripod.com/formats/exe-LE.htm
	 */
	public long page_offset_shift;			/* 2Ch */
	public long fixup_section_size;			/* 30h */
	public long fixup_section_check_sum;	/* 34h */
	public long loader_section_size;		/* 38h */
	public long loader_section_check_sum;	/* 3Ch */
	public long object_table_offset;		/* 40h */
	public long objects_in_module;			/* 44h */
	public long object_page_table_offset;	/* 48h */
	public long object_iter_page_offset;	/* 4ch */
	public long resource_table_offset;		/* 50h */
	public long resource_table_entries;		/* 54h */
	public long residance_name_tbl_offset;	/* 58h */
	public long entry_table_offset;			/* 5Ch */
	public long module_directives_offset;	/* 60h */
	public long module_directives_count;	/* 64h */
	public long fixup_page_table_offset;	/* 68h */
	public long fixup_record_table_offset;	/* 6Ch */
	public long import_module_name_table_offset; /* 70h */
	public long import_module_name_entry_count; /* 74h */
	public long import_procedure_name_table_offset;	/* 78h */
	public long per_page_checksum_offset;	/* 7Ch */
	public long data_pages_offset;			/* 80h */
	public long preload_pages;				/* 84h */
	public long non_resident_name_tvl_offset; /* 88h */
	public long non_resident_name_tbl_len;	/* 8Ch */
	public long non_resident_name_tbl_cksm;	/* 90h */
	public long auto_ds_object;				/* 94h */
	public long debug_info_offset;			/* 98h */
	public long debug_info_len;				/* 9Ch */
	public long instance_preload;			/* A0h */
	public long instance_demand;			/* A4h */
	public long heapsize;					/* A8h */

	
	public LXHeader(BinaryReader reader) throws IOException {
		signature = reader.readNextAsciiString(2);
		if (!signature.equals("LX") && !signature.equals("LE")) {
			throw new UnknownError("Unknwon file format: " + signature);
		}
		
		b_ord = reader.readNextByte();
		if (b_ord != 0) {
			throw new UnknownError("Unsuported big endian");
		}
		w_ord = reader.readNextByte();
		if (w_ord != 0) {
			throw new UnknownError("Unsuported big endian");
		}
		format_level = reader.readNextUnsignedInt();
		if (w_ord != 0) {
			throw new UnknownError("Unsuported format lvl");
		}
		cpu_type = reader.readNextUnsignedShort();
		os_type = reader.readNextUnsignedShort();
		module_version = reader.readNextUnsignedInt();
		module_flag = reader.readNextUnsignedInt();
		module_of_pages = reader.readNextUnsignedInt();
		eip_object = reader.readNextUnsignedInt();
		eip = reader.readNextUnsignedInt();
		esp_object = reader.readNextUnsignedInt();
		esp = reader.readNextUnsignedInt();
		page_size = reader.readNextUnsignedInt();
		page_offset_shift = reader.readNextUnsignedInt();
		fixup_section_size = reader.readNextUnsignedInt();
		fixup_section_check_sum = reader.readNextUnsignedInt();
		loader_section_size = reader.readNextUnsignedInt();
		loader_section_check_sum = reader.readNextUnsignedInt();
		object_table_offset = reader.readNextUnsignedInt();
		objects_in_module = reader.readNextUnsignedInt();
		object_page_table_offset = reader.readNextUnsignedInt();
		object_iter_page_offset = reader.readNextUnsignedInt();
		resource_table_offset = reader.readNextUnsignedInt();
		resource_table_entries = reader.readNextUnsignedInt();
		residance_name_tbl_offset = reader.readNextUnsignedInt();
		entry_table_offset = reader.readNextUnsignedInt();
		module_directives_offset = reader.readNextUnsignedInt();
		module_directives_count = reader.readNextUnsignedInt();
		fixup_page_table_offset = reader.readNextUnsignedInt();
		fixup_record_table_offset = reader.readNextUnsignedInt();
		import_module_name_table_offset = reader.readNextUnsignedInt();
		import_module_name_entry_count = reader.readNextUnsignedInt();
		import_procedure_name_table_offset = reader.readNextUnsignedInt();
		per_page_checksum_offset = reader.readNextUnsignedInt();
		data_pages_offset = reader.readNextUnsignedInt();
		preload_pages = reader.readNextUnsignedInt();
		non_resident_name_tvl_offset = reader.readNextUnsignedInt();
		non_resident_name_tbl_len = reader.readNextUnsignedInt();
		non_resident_name_tbl_cksm = reader.readNextUnsignedInt();
		auto_ds_object = reader.readNextUnsignedInt();
		debug_info_offset = reader.readNextUnsignedInt();
		debug_info_len = reader.readNextUnsignedInt();
		instance_preload = reader.readNextUnsignedInt();
		instance_demand = reader.readNextUnsignedInt();
		heapsize = reader.readNextUnsignedInt();
	}
	
	public DataType toDataType() {
		Structure struct = new StructureDataType("LXHeader_t", 0);
		struct.add(ASCII, 2, "signature", null);
		struct.add(DWORD, 1, "b_ord", null);
		struct.add(DWORD, 1, "w_ord", null);
		struct.add(DWORD, 4, "format_level", null);
		struct.add(DWORD, 2, "cpu_type", null);
		struct.add(DWORD, 2, "os_type", null);
		struct.add(DWORD, 4, "module_version", null);
		struct.add(DWORD, 4, "module_flag", null);
		struct.add(DWORD, 4, "module_of_pages", null);
		struct.add(DWORD, 4, "eip_object", null);
		struct.add(DWORD, 4, "eip", null);
		struct.add(DWORD, 4, "esp_object", null);
		struct.add(DWORD, 4, "esp", null);
		struct.add(DWORD, 4, "page_size", null);
		struct.add(DWORD, 4, "page_offset_shift", null);
		struct.add(DWORD, 4, "fixup_section_size", null);
		struct.add(DWORD, 4, "fixup_section_check_sum", null);
		struct.add(DWORD, 4, "loader_section_size", null);
		struct.add(DWORD, 4, "loader_section_check_sum", null);
		struct.add(DWORD, 4, "object_table_offset", null);
		struct.add(DWORD, 4, "objects_in_module", null);
		struct.add(DWORD, 4, "object_page_table_offset", null);
		struct.add(DWORD, 4, "object_iter_page_offset", null);
		struct.add(DWORD, 4, "resource_table_offset", null);
		struct.add(DWORD, 4, "resource_table_entries", null);
		struct.add(DWORD, 4, "residance_name_tbl_offset", null);
		struct.add(DWORD, 4, "entry_table_offset", null);
		struct.add(DWORD, 4, "module_directives_offset", null);
		struct.add(DWORD, 4, "module_directives_count", null);
		struct.add(DWORD, 4, "fixup_page_table_offset", null);
		struct.add(DWORD, 4, "fixup_record_table_offset", null);
		struct.add(DWORD, 4, "import_module_name_table_offset", null);
		struct.add(DWORD, 4, "import_module_name_entry_count", null);
		struct.add(DWORD, 4, "import_procedure_name_table_offset", null);
		struct.add(DWORD, 4, "per_page_checksum_offset", null);
		struct.add(DWORD, 4, "data_pages_offset", null);
		struct.add(DWORD, 4, "preload_pages", null);
		struct.add(DWORD, 4, "non_resident_name_tvl_offset", null);
		struct.add(DWORD, 4, "non_resident_name_tbl_len", null);
		struct.add(DWORD, 4, "non_resident_name_tbl_cksm", null);
		struct.add(DWORD, 4, "auto_ds_object", null);
		struct.add(DWORD, 4, "debug_info_offset", null);
		struct.add(DWORD, 4, "debug_info_len", null);
		struct.add(DWORD, 4, "instance_preload", null);
		struct.add(DWORD, 4, "instance_demand", null);
		struct.add(DWORD, 4, "heapsize", null);
		return struct;
	}
}
