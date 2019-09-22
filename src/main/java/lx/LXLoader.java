/* ###
 * IP: GHIDRA
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
import java.io.InputStream;
import java.util.*;

import org.python.modules.math;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class LXLoader extends AbstractLibrarySupportLoader {
	long base_addr;
	
	@Override
	public String getName() {
		return "Linear eXecutable Module Format";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		BinaryReader reader = new BinaryReader(provider, true);
		if (reader.readNextAsciiString(2).equals("MZ") /*&&
		XXX: This should work for other but dos not for MK.
			reader.readByte(0x18) >= 0x40) {
		*/
				) {
			return List.of(new LoadSpec(this, 0, new LanguageCompilerSpecPair("x86:LE:32:default", "gcc"), true));
		}
		
		return new ArrayList<>();
	}
	
	protected LXObjectTable[] loadObjectTable(LXHeader header, BinaryReader reader) throws IOException{
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

	protected LXObjectPageTable[] loadObjectPageTable(LXHeader header, BinaryReader reader) throws IOException{
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
	
	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, MemoryConflictHandler handler, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		BinaryReader reader = new BinaryReader(provider, true);
		FlatProgramAPI api = new FlatProgramAPI(program, monitor);
		LXHeader header;
		LXObjectTable []object_table;
		LXObjectPageTable []object_page_table;
		
		/* XXX: This address should be obtained from 0x3c */
		base_addr = 0x8fc8;
		base_addr = 0x292E4;
		
		reader.setPointerIndex(base_addr);
		header = new LXHeader(reader);
		object_table = loadObjectTable(header, reader);
		// Assume that file is flat.
		object_page_table = loadObjectPageTable(header, reader);
		
		reader.setPointerIndex(0);
		for (int hoi = 0; hoi < object_table.length; hoi++) {
			String name;
			MemoryBlock block;
			LXObjectTable ohdr = object_table[hoi];
			System.out.printf("%x\n", ohdr.object_flags);
			
			if ((ohdr.object_flags & 0x40) != 0x40) {
				continue;
			}

			if ((ohdr.object_flags & 0x04) == 0x04) {
				name = "code";
			} else {
				name = "seg";
			}

			name += Integer.toString(hoi);
			byte []data = new byte[(int)ohdr.virtual_size];
			int count = (int)Math.min(ohdr.page_table_index + ohdr.page_table_entries, header.module_of_pages);
			long datapos = 0;
			for (int oi = (int)ohdr.page_table_index; oi < count; oi++) {
				LXObjectPageTable obj = object_page_table[oi];
				long addr = (obj.page_data_offset + obj.data_size - 1) * header.page_size + header.data_pages_offset;
				//long addr = header.data_pages_offset + ohdr.page_table_index
				//long addr = obj.page_data_offset;
				long rsize;
				
				if (oi + 1 < header.module_of_pages)
					rsize = Math.min(ohdr.virtual_size - datapos, header.page_size); 
				else
					rsize = Math.min(ohdr.virtual_size - datapos, header.page_offset_shift);
				System.out.println(addr);
				byte []xdata = reader.readByteArray(addr, (int)rsize);
				System.arraycopy(xdata, 0, data, (int)datapos, (int)rsize);
				
				datapos += rsize;
			}
			
			try {
				block = api.createMemoryBlock(name, api.toAddr(ohdr.reloc_base_addr), data, true);
				block.setRead((ohdr.object_flags & 0x01) == 0x01);
	        	block.setWrite((ohdr.object_flags & 0x02) == 0x02);
	        	block.setExecute((ohdr.object_flags & 0x04) == 0x04);
			} catch (Exception e) {
				Msg.error(this, e.getMessage());
			}
		}
		
   	 	api.addEntryPoint(api.toAddr(header.eip));
        api.createFunction(api.toAddr(header.eip), "_entry");
	}
}
