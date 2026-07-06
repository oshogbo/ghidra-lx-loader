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

import ghidra.app.util.bin.BinaryReader;

/*
 * [Doc] docs/lxexe.txt "Object Page Table" (LX),
 * docs/exeflat.h lx_map_entry/le_map_entry,
 * docs/exe_vxd.h o32_map and GETPAGEIDX (LE).
 *
 * LX object page table entry (8 bytes):
 *        63                     32 31       16 15         0
 *         +-----+-----+-----+-----+-----+-----+-----+-----+
 *     00h |    PAGE DATA OFFSET   | DATA SIZE |   FLAGS   |
 *         +-----+-----+-----+-----+-----+-----+-----+-----+
 *
 * PAGE DATA OFFSET is relative to the data pages offset and is
 * left-shifted by the header's page offset shift; DATA SIZE is the
 * number of bytes present in the file (the rest of the page is
 * zero-filled).
 *
 * LE object page table entry (4 bytes): a 24-bit big-endian page
 * number followed by a flags byte; pages are stored consecutively,
 * page_size each.
 *
 * FLAGS:
 *   00h = Legal Physical Page in the module.
 *   01h = Iterated Data Page.
 *   02h = Invalid Page.
 *   03h = Zero Filled Page.
 *   04h = Range of pages.
 */
public class LXObjectPageTable {
	// LX format
	public long page_data_offset;
	public int data_size;

	// LE format
	public long page_num;

	public int flags;

	public LXObjectPageTable(BinaryReader reader, boolean bisLe) throws IOException {

		if (bisLe) {
			page_num = reader.readNextUnsignedByte();
			page_num = page_num << 8;
			page_num |= reader.readNextUnsignedByte();
			page_num = page_num << 8;
			page_num |= reader.readNextUnsignedByte();
			flags = reader.readNextUnsignedByte();
		} else {
			page_data_offset = reader.readNextUnsignedInt();
			data_size = reader.readNextUnsignedShort();
			flags = reader.readNextUnsignedShort();
		}

		if (flags > 4) {
			throw new UnknownError("Wrong flags" + Integer.toString(flags));
		}
	}
}
