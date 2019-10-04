package lx;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.mem.MemoryBlock;

/*
 *         +-----+-----+-----+-----+-----+-----+-----+-----+
 *     00h |     VIRTUAL SIZE      |    RELOC BASE ADDR    |
 *         +-----+-----+-----+-----+-----+-----+-----+-----+
 *     08h |     OBJECT FLAGS      |    PAGE TABLE INDEX   |
 *         +-----+-----+-----+-----+-----+-----+-----+-----+
 *     10h |  # PAGE TABLE ENTRIES |       RESERVED        |
 *         +-----+-----+-----+-----+-----+-----+-----+-----+
 */

public class LXObjectTable {
	public long virtual_size;
	public long reloc_base_addr;
	public long object_flags;
	public long page_table_index;
	public long page_table_entries;
	public long reserved;
	
	public LXObjectTable(BinaryReader reader) throws IOException {
		virtual_size = reader.readNextUnsignedInt();
		reloc_base_addr = reader.readNextUnsignedInt();
		object_flags = reader.readNextUnsignedInt();
		page_table_index = reader.readNextUnsignedInt() - 1;
		page_table_entries = reader.readNextUnsignedInt();
		reserved = reader.readNextUnsignedInt();
	}

	public boolean isReadable() {
		return (object_flags & 0x01) == 0x01;
	}
	
	public boolean isWritable() {
		return (object_flags & 0x02) == 0x02;
	}
	
	public boolean isExecutable() {
		return (object_flags & 0x04) == 0x04;
	}
	
	public boolean objectHasPreloadPages() {
		return (object_flags & 0x40) == 0x40;
	}

	public String getName() {
		return isExecutable() ? "code" : "seg";
	}
	
	public void setObjectPermissions(MemoryBlock block) {
		block.setRead(isReadable());
    	block.setWrite(isWritable());
    	block.setExecute(isExecutable());
	}
	
	/*
    private void createObject(FlatProgramAPI api) {
    	MemoryBlock block = api.createMemoryBlock(,, api.toAddr(relac_base_addres), virtual_size, false);
        
    	block.setRead((object_flags & 0x01) == 0x01);
        block.setWrite((object_flags & 0x02) == 0x02);
        block.setExecute((object_flags & 0x04) == 0x04);
    }
    */
	
}
