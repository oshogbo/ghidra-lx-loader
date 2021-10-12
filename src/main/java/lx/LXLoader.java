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
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class LXLoader extends AbstractLibrarySupportLoader {
	
	public long 						exeoffset;
	public long 						linoffset;
		
	
	@Override
	public String getName() {
		return "Linear eXecutable Module Format";
	}
	
	public boolean findStartOffset(BinaryReader reader) throws IOException {
		String signature;
		long 	datalen;
		long 	offset;
		int		exelen, tmp;
		

		// skip any stub data
		offset = 0;
		exeoffset = 0;
		datalen = reader.length();
		
		while(datalen > 2)
		{
			signature = reader.readAsciiString(offset, 2);		
			/* Standalone LE/LX file */
			if ("LE".equals(signature) || "LX".equals(signature)) {
				linoffset = offset;
				return true;
			}
			
			if("MZ".equals(signature))
			{
				/* save the start of this exe file as the last exe offset */
				exeoffset = offset;
				/* got an embedded LE */ 
				if(reader.readByte(offset + 0x18) >= 0x40) {	
					
					offset += reader.readUnsignedInt(offset + 0x3C);
					
					continue;
				}
				
				/*  mz stub header, skip */
				exelen = reader.readUnsignedShort(offset + 0x04);
				exelen *= 512;
				tmp = reader.readUnsignedShort(offset + 0x02);
				if(tmp != 0)
					exelen -= (512 - tmp);
				
				offset += exelen;
				datalen -= exelen;
			}
			else if("BW".equals(signature))
			{
				/* 
				 * DOS/4G Executable
				 * exp stub header, skip
				 */
				exelen = reader.readUnsignedShort(offset + 0x04);
				exelen *= 512;
				tmp = reader.readUnsignedShort(offset + 0x02);
				if(tmp != 0)
					exelen += tmp;
				
				offset += exelen;
				datalen -= exelen;
			}
			else
				/* unknown/invalid stub header signature */
				break;			
		}
		
		/* no linear executable found */
		return false;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		BinaryReader reader = new BinaryReader(provider, true);
	
		// skip any stub data
		if(!findStartOffset(reader))
			// no linear executable found
			return List.of();
		else
			return List.of(new LoadSpec(this, 0, new LanguageCompilerSpecPair("x86:LE:32:default", "gcc"), true));
	}
	
	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		LX lx;
		long base_addr;
		BinaryReader reader = new BinaryReader(provider, true);
		FlatProgramAPI api = new FlatProgramAPI(program, monitor);
		

	    if(!findStartOffset(reader))
	    	throw new CancelledException();

	    base_addr = linoffset;
	    
		
		/* Parse LX/LE. */
		lx = new LX(reader, base_addr, exeoffset);
			
		/* Create segments. */
		for (int hoi = 0; hoi < lx.sizeOfLXObjectTable(); hoi++) {
			LXObjectTable ohdr = lx.getLXObjectTable(hoi);
			String name = ohdr.getName() + Integer.toString(hoi + 1);
			MemoryBlock block;
			byte []data;
			
			if(!lx.getHeader().isLe && !ohdr.objectHasPreloadPages()) 
				continue;

			data = lx.readObjectData(reader, ohdr);
			
			try {
				block = api.createMemoryBlock(name, api.toAddr(ohdr.reloc_base_addr), data, false);
				ohdr.setObjectPermissions(block);
			} catch (Exception e) {
				Msg.error(this, e.getMessage());
			}
		}
		
		api.addEntryPoint(api.toAddr(lx.getEIPAddress()));
		api.disassemble(api.toAddr(lx.getEIPAddress()));
		api.createFunction(api.toAddr(lx.getEIPAddress()), "_entry");
	}
}
