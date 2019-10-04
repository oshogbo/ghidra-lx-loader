package lx;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

public class LX {
	private long base_addr;
	private LXHeader header;
	private LXObjectTable []object_table;
	private LXObjectPageTable []object_page_table;
	
	protected LXObjectTable[] loadObjectTable(BinaryReader reader) throws IOException {
		/*
		 * public long object_table_offset;		 40h 
		 * public long objects_in_module;		 44h 
		 */
		LXObjectTable []opt;
		
		reader.setPointerIndex(base_addr + header.object_table_offset);
		opt = new LXObjectTable[(int)header.objects_in_module];
		for (int i = 0; i < (int)header.objects_in_module; i++) {
			opt[i] = new LXObjectTable(reader);
		}
		
		return opt;
	}

	protected LXObjectPageTable[] loadObjectPageTable(BinaryReader reader) throws IOException {
		/*
		 * public long	module_of_pages;			 14h 
		 * public long object_iter_page_offset;		 4ch
		 */
		LXObjectPageTable []opt;
		
		System.out.printf("osho %d %d", base_addr, header.object_page_table_offset);
		reader.setPointerIndex(base_addr + header.object_page_table_offset);
		opt = new LXObjectPageTable[(int)header.module_of_pages];
		for (int i = 0; i < (int)header.module_of_pages; i++) {
			opt[i] = new LXObjectPageTable(reader);
		}
		
		return opt;
	}
	
	protected LXFixup loadFixup(BinaryReader) throws IOException {
		
	}
	
	public LX(BinaryReader reader, long base_addr) throws IOException {
		this.base_addr = base_addr;
		reader.setPointerIndex(base_addr);

		header = new LXHeader(reader);
		object_table = loadObjectTable(reader);
		object_page_table = loadObjectPageTable(reader);
		fixup = loadFixup(reader);
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
		
		return (opt.page_data_offset + opt.data_size - 1) *
				header.page_size + header.data_pages_offset;
	}
	
	private long getPageFileSize(LXObjectTable ohdr, int oi, long datapos) {
		assert(oi + 1 <= header.module_of_pages);
		
		if (oi + 1 == header.module_of_pages) 
			return Math.min(ohdr.virtual_size - datapos, header.page_offset_shift);

		return Math.min(ohdr.virtual_size - datapos, header.page_size);
	}
	
	private int getPageEndIndex(LXObjectTable ohdr) {
		return (int)Math.min(ohdr.page_table_index + ohdr.page_table_entries, header.module_of_pages);
	}
	
	public byte[] readObjectData(BinaryReader reader, LXObjectTable ohdr) throws IOException {
		byte []data = new byte[(int)ohdr.virtual_size];
		int page_end_i = getPageEndIndex(ohdr);
		int datapos = 0;
		
		for (int oi = (int)ohdr.page_table_index; oi < page_end_i; oi++) {
			int rsize = (int)getPageFileSize(ohdr, oi, datapos);
			byte []xdata = reader.readByteArray(getPageFileOffset(oi), rsize);
			
			System.arraycopy(xdata, 0, data, datapos, rsize);
			datapos += rsize;
		}
		
		return data;
	}
}