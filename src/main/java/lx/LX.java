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
import java.util.LinkedHashMap;
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Msg;

public class LX {
	private long base_addr;
	private LXHeader header;
	private LXObjectTable []object_table;
	private LXObjectPageTable []object_page_table;
	private LXFixupPageTable []fixup_page_table;
	private String []import_module_names;
	/* Import slot address keyed by label, insertion ordered. */
	private LinkedHashMap<String, Long> import_slots = new LinkedHashMap<String, Long>();
	private long import_base;

	protected LXObjectTable[] loadObjectTable(BinaryReader reader) throws IOException {
		/*
		 * [Doc]
		 * public long object_table_offset;		 40h
		 * public long objects_in_module;		 44h
		 */
		LXObjectTable []opt = new LXObjectTable[(int)header.objects_in_module];

		reader.setPointerIndex(base_addr + header.object_table_offset);
		for (int i = 0; i < (int)header.objects_in_module; i++) {
			opt[i] = new LXObjectTable(reader);
		}

		return opt;
	}

	protected LXObjectPageTable[] loadObjectPageTable(BinaryReader reader) throws IOException {
		/*
		 * [Doc]
		 * public long	module_of_pages;		14h
		 * public long object_iter_page_offset;		4ch
		 */
		LXObjectPageTable []opt = new LXObjectPageTable[(int)header.module_of_pages];

		reader.setPointerIndex(base_addr + header.object_page_table_offset);
		for (int i = 0; i < (int)header.module_of_pages; i++) {
			opt[i] = new LXObjectPageTable(reader, header.isLe());
		}

		return opt;
	}

	protected LXFixupPageTable[] loadFixupPageTable(BinaryReader reader) throws IOException {
		/*
		 * [Doc]
		 * This table is parallel to the Object Page Table, except that
		 * there is one  additional entry in this table to indicate the
		 * end of the Fixup Record Table.
		 * public long	module_of_pages;		14h
		 *
		 * public long fixup_page_table_offset;		68h
		 */
		LXFixupPageTable []fpt = new LXFixupPageTable[(int)header.module_of_pages + 1];

		reader.setPointerIndex(base_addr + header.fixup_page_table_offset);
		for (int i = 0; i < (int)header.module_of_pages + 1; i++) {
			fpt[i] = new LXFixupPageTable(reader);
		}

		return fpt;
	}

	protected void loadFixupRecordTable(BinaryReader reader) throws IOException {
		/*
		 * [Doc]
		 * public long fixup_record_table_offset;	6Ch
		 */
		LXFixupRecordTable frt;
		LXObjectTable ot;
		long start, end, base_offset;
		int page_end_i;

		for (int i = 0; i < (int)header.objects_in_module; i++) {
			ot = getLXObjectTable(i);
			page_end_i = getPageEndIndex(ot);

			for (int oi = (int)ot.page_table_index; oi < page_end_i; oi++) {
				start = base_addr + header.fixup_record_table_offset + fixup_page_table[oi].offset;
				end = base_addr + header.fixup_record_table_offset + fixup_page_table[oi + 1].offset;
				base_offset = (oi - ot.page_table_index) * header.page_size;

				reader.setPointerIndex(start);
				while (start < end) {
					frt = new LXFixupRecordTable(reader, base_offset);
					ot.appendFixupTable(frt);
					start += frt.getSizeInFile();
				}
			}
		}
	}

	private long pageAlign(long addr) {
		return ((addr + header.page_size - 1) / header.page_size) * header.page_size;
	}

	protected void assignBaseAddresses() {
		/*
		 * Objects with a zero reloc_base_addr (every object of a
		 * VxD-style module, resource objects of OS/2 executables)
		 * rely on the loader to place them, as does an object whose
		 * header base collides with another object: internal fixups
		 * carry an (object number, offset) pair, so any consistent
		 * assignment works. Move only those objects, page aligned,
		 * past the end of every placed object; objects with sane
		 * header bases stay where the linker put them.
		 */
		boolean []move = new boolean[object_table.length];
		long next_free = 0x10000;

		for (int i = 0; i < object_table.length; i++) {
			LXObjectTable a = object_table[i];

			move[i] = a.reloc_base_addr == 0;
			for (int j = 0; j < i && !move[i]; j++) {
				LXObjectTable b = object_table[j];

				if (move[j])
					continue;
				if (a.reloc_base_addr < b.reloc_base_addr + b.virtual_size &&
				    b.reloc_base_addr < a.reloc_base_addr + a.virtual_size)
					move[i] = true;
			}
			if (!move[i])
				next_free = Math.max(next_free,
				    pageAlign(a.reloc_base_addr + a.virtual_size));
		}

		for (int i = 0; i < object_table.length; i++) {
			if (!move[i])
				continue;

			Msg.info(this, String.format(
			    "Object %d has no usable base address, placing it at 0x%x",
			    i + 1, next_free));
			object_table[i].reloc_base_addr = next_free;
			next_free = pageAlign(next_free + object_table[i].virtual_size);
		}
	}

	protected String[] loadImportModuleNameTable(BinaryReader reader) throws IOException {
		/*
		 * [Doc]
		 * public long import_module_name_table_offset;	70h
		 * public long import_module_name_entry_count;	74h
		 *
		 * Length-prefixed strings, back to back.
		 */
		String []names = new String[(int)header.import_module_name_entry_count];

		reader.setPointerIndex(base_addr + header.import_module_name_table_offset);
		for (int i = 0; i < names.length; i++) {
			int len = reader.readNextUnsignedByte();
			names[i] = reader.readNextAsciiString(len);
		}

		return names;
	}

	private String importModuleName(long i) {
		if (i >= 0 && i < import_module_names.length)
			return import_module_names[(int)i];
		return "module" + (i + 1);
	}

	private String readImportProcedureName(BinaryReader reader, long offset) throws IOException {
		/*
		 * [Doc]
		 * public long import_procedure_name_table_offset;	78h
		 *
		 * Length-prefixed strings; fixup records reference them by
		 * byte offset into the table.
		 */
		reader.setPointerIndex(base_addr +
		    header.import_procedure_name_table_offset + offset);
		int len = reader.readNextUnsignedByte();
		return reader.readNextAsciiString(len);
	}

	protected void assignImportSlots(BinaryReader reader) throws IOException {
		/*
		 * Give every unique import target a 4-byte slot in a
		 * synthetic block placed past the last object, so fixup
		 * sites have a concrete address to point at; the loader
		 * labels each slot with the module and procedure.
		 */
		LXObjectTable ot;
		Iterator<LXFixupRecordTable> itr;
		LXFixupRecordTable frt;
		String label;

		import_base = 0x10000;
		for (int i = 0; i < object_table.length; i++) {
			ot = object_table[i];
			import_base = Math.max(import_base,
			    pageAlign(ot.reloc_base_addr + ot.virtual_size));
		}

		for (int i = 0; i < object_table.length; i++) {
			itr = object_table[i].fixupTableIterator();
			while (itr.hasNext()) {
				frt = itr.next();

				switch (frt.getTargetType()) {
				case 0x01: /* Imported by ordinal. */
					label = importModuleName(frt.module) +
					    "_Ord" + frt.import_ordinal;
					break;
				case 0x02: /* Imported by name. */
					label = importModuleName(frt.module) + "_" +
					    readImportProcedureName(reader, frt.name_offset);
					break;
				default:
					continue;
				}
				label = label.replaceAll("[^A-Za-z0-9_]", "_");

				if (!import_slots.containsKey(label)) {
					import_slots.put(label,
					    import_base + import_slots.size() * 4L);
				}
				frt.import_addr = import_slots.get(label);
			}
		}
	}

	public boolean hasImports() {
		return !import_slots.isEmpty();
	}

	public long getImportBlockBase() {
		return import_base;
	}

	public long getImportBlockSize() {
		return import_slots.size() * 4L;
	}

	public Map<String, Long> getImportSlots() {
		return import_slots;
	}

	public LX(BinaryReader reader, long base_addr, long exeoffset) throws IOException {
		this.base_addr = base_addr;
		reader.setPointerIndex(base_addr);

		header = new LXHeader(reader);
		/*
		 * data_pages_offset contains the offset relative to the exe start
		 * in an MZ/LE, add the offset to the beginning of the embedded exe.
		 */
		header.data_pages_offset += exeoffset;

		object_table = loadObjectTable(reader);
		assignBaseAddresses();
		object_page_table = loadObjectPageTable(reader);
		fixup_page_table = loadFixupPageTable(reader);
		loadFixupRecordTable(reader);
		import_module_names = loadImportModuleNameTable(reader);
		assignImportSlots(reader);
	}

	public LXHeader getHeader() {
		return header;
	}

	public LXObjectTable getLXObjectTable(int i) {
		return object_table[i];
	}

	public LXObjectPageTable getLXObjectPageTable(int oi) {
		return object_page_table[oi];
	}

	public long sizeOfLXObjectTable() {
		return object_table.length;
	}

	private long getPageFileOffset(int oi) {
		LXObjectPageTable opt = getLXObjectPageTable(oi);

		if (header.isLe())
			return (opt.page_num-1) * header.page_size + header.data_pages_offset;

		/*
		 * [Doc]
		 * LX: the page data offset is left-shifted by the page
		 * offset shift and is relative to the data pages offset.
		 */
		return (opt.page_data_offset << header.page_offset_shift) +
				header.data_pages_offset;
	}

	private long getPageFileSize(LXObjectTable ohdr, int oi, long datapos) {
		assert(oi + 1 <= header.module_of_pages);

		/*
		 * [Doc]
		 * Header offset 2Ch is "bytes on last page" for LE, but
		 * "page offset shift" for LX; an LX page instead carries
		 * its own data size in the page table entry (the rest of
		 * the page is zero-filled).
		 */
		if (header.isLe()) {
			if (oi + 1 == header.module_of_pages)
				return Math.min(ohdr.virtual_size - datapos, header.page_offset_shift);
			return Math.min(ohdr.virtual_size - datapos, header.page_size);
		}
		return Math.min(ohdr.virtual_size - datapos,
				getLXObjectPageTable(oi).data_size);
	}

	private int getPageEndIndex(LXObjectTable ohdr) {
		return (int)Math.min(ohdr.page_table_index + ohdr.page_table_entries, header.module_of_pages);
	}

	/* Can I do it better in java? ... */
	private void emitU16(byte []data, int offset, long val) {
		data[offset] = (byte)((val) & 0xFF);
		data[offset + 1] = (byte)((val >> 8) & 0xFF);
	}
	private void emitU32(byte []data, int offset, long val) {
		data[offset] = (byte)((val) & 0xFF);
		data[offset + 1] = (byte)((val >> 8) & 0xFF);
		data[offset + 2] = (byte)((val >> 16) & 0xFF);
		data[offset + 3] = (byte)((val >> 24) & 0xFF);
	}
	/* ... Probably */

	private void applyFixups(LXObjectTable ot, byte []data) {
		Iterator<LXFixupRecordTable> itr = ot.fixupTableIterator();
		LXFixupRecordTable frt;
		long memAddr;

		while (itr.hasNext()) {
			frt = itr.next();

			if (frt.getSourceType() == 0x02) {
				/* XXX: What supposed should I do? */
				continue;
			}

			switch (frt.getTargetType()) {
			case 0x00: /* Internal reference. */
				memAddr = getLXObjectTable((int)frt.object).reloc_base_addr +
				    frt.trgoff;
				break;
			case 0x01: /* Imported by ordinal. */
			case 0x02: /* Imported by name. */
				/* Slot assigned by assignImportSlots(). */
				memAddr = frt.import_addr;
				break;
			default: /* 0x03, internal via entry table. */
				Msg.warn(this, "Entry table fixup not supported, skipping");
				continue;
			}
			memAddr += frt.additive;

			for (int i = 0; i < frt.getDSTOffsetCount(); i++) {
				/*
				 * [Doc] docs/lxexe.txt, note under SRCOFF:
				 * A fixup that crosses a page boundary gets a
				 * separate record for each page; the second
				 * page's offset is negative, back into the
				 * preceding page. Both records write the same
				 * value at the same object offset, and object
				 * data is contiguous here, so applying them is
				 * idempotent; only writes that would leave the
				 * object entirely (first or last page of the
				 * object) are skipped.
				 */
				int width = frt.getSourceType() == 0x03 ||
				    frt.getSourceType() == 0x05 ? 2 : 4;

				if (frt.getDSTOffset(i) < 0 ||
				    frt.getDSTOffset(i) + width > data.length) {
					continue;
				}

				switch (frt.getSourceType()) {
				case 0x03:
					/*
					 * 16:16 Pointer — 32 bits on disk: 16-bit offset at +0,
					 * 16-bit selector at +2. Open Watcom's DOS/32A loader
					 * (fix_1616ptr in contrib/extender/dos32a/src/dos32a/
					 * loader.asm) writes both halves:
					 *   mov gs:[edi+0], ax   ; offset
					 *   mov gs:[edi+2], dx   ; selector (from object table)
					 * Ghidra analyzes as x86:LE:32 (flat), so the selector
					 * has no meaningful analog; we write the offset only
					 * and leave +2 alone — same compromise the existing
					 * 0x06 (16:32) handler makes with its selector half.
					 */
					emitU16(data, frt.getDSTOffset(i), memAddr);
					break;
				case 0x05: /* 16-bit */
					emitU16(data, frt.getDSTOffset(i), memAddr);
					break;
				case 0x06: /* 16:32 bit Pointer */
					/* XXX: What todo ? */
					emitU32(data, frt.getDSTOffset(i), memAddr);
					break;
				case 0x07: /* 32-bit */
					emitU32(data, frt.getDSTOffset(i), memAddr);
					break;
				case 0x08: /* 32-bit Self-relative offset fixup */
					/*
					 * The stored value is relative to the end of
					 * the 32-bit source field: target - (site + 4).
					 * Open Watcom's DOS/32A loader agrees
					 * (fix_relofs32 in loader.asm: subtracts the
					 * site address and 4 from the target).
					 */
					emitU32(data, frt.getDSTOffset(i),
					    memAddr - (ot.reloc_base_addr + frt.getDSTOffset(i) + 4));
					break;
				}
			}
		}
	}

	public byte[] readObjectData(BinaryReader reader, LXObjectTable ot) throws IOException {
		byte []data = new byte[(int)ot.virtual_size];
		int page_end_i = getPageEndIndex(ot);
		int datapos = 0;

		for (int oi = (int)ot.page_table_index; oi < page_end_i; oi++) {
			switch (getLXObjectPageTable(oi).flags) {
			case 0x00: /* Legal Physical Page. */
				int rsize = (int)getPageFileSize(ot, oi, datapos);
				byte []xdata = reader.readByteArray(getPageFileOffset(oi), rsize);

				System.arraycopy(xdata, 0, data, datapos, rsize);
				break;
			case 0x02: /* Invalid Page. */
			case 0x03: /* Zero Filled Page. */
				break;
			default:
				Msg.warn(this, String.format(
				    "Unsupported page flags 0x%x, leaving page %d zeroed",
				    getLXObjectPageTable(oi).flags, oi + 1));
				break;
			}

			/*
			 * A page occupies page_size bytes in memory no matter
			 * how many bytes the file provides for it.
			 */
			datapos += (int)Math.min(ot.virtual_size - datapos, header.page_size);
		}

		applyFixups(ot, data);

		return data;
	}

	public boolean hasEIP() {
		/* eip_object is -1 when the EIP object number in the header is 0 (no entry point). */
		return header.eip_object >= 0 && header.eip_object < object_table.length;
	}

	public long getEIPAddress() {
		return getLXObjectTable((int)header.eip_object).reloc_base_addr + header.eip;
	}
}
