/*-
 * Copyright 2019 Mariusz Zaborski <oshogbo@FreeBSD.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package lx;

import java.io.IOException;
import java.util.Iterator;
import java.util.LinkedList;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.mem.MemoryBlock;

/*
 * [Doc]
 *         +-----+-----+-----+-----+-----+-----+-----+-----+
 *     00h |     VIRTUAL SIZE      |    RELOC BASE ADDR    |
 *         +-----+-----+-----+-----+-----+-----+-----+-----+
 *     08h |     OBJECT FLAGS      |    PAGE TABLE INDEX   |
 *         +-----+-----+-----+-----+-----+-----+-----+-----+
 *     10h |  # PAGE TABLE ENTRIES |       RESERVED        |
 *         +-----+-----+-----+-----+-----+-----+-----+-----+
 */

public class LXObjectTable {
	/* Struct ones. */
	public long virtual_size;
	public long reloc_base_addr;
	public long object_flags;
	public long page_table_index;
	public long page_table_entries;
	public long reserved;
	
	/* My private ones. */
	private LinkedList<LXFixupRecordTable> fixups_for_opbject = new LinkedList<LXFixupRecordTable>();
	
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
		return isExecutable() ? "cseg" : "dseg";
	}
	
	public void setObjectPermissions(MemoryBlock block) {
		block.setRead(isReadable());
		block.setWrite(isWritable());
		block.setExecute(isExecutable());
	}
	
	public void appendFixupTable(LXFixupRecordTable fr) {
		fixups_for_opbject.add(fr);
	}
	
	public Iterator<LXFixupRecordTable> fixupTableIterator() {
		return fixups_for_opbject.iterator();
	}
}
