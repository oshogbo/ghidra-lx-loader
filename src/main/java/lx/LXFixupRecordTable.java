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

public class LXFixupRecordTable {
	/*
	 *         +-----+-----+-----+-----+
	 *     00h | SRC |FLAGS|SRCOFF/CNT*|
	 *	   +-----+-----+-----+-----+-----+-----+
	 * 03h/04h |           TARGET DATA *           |
	 *         +-----+-----+-----+-----+-----+-----+
	 *         | SRCOFF1 @ |   . . .   | SRCOFFn @ |
	 *         +-----+-----+----   ----+-----+-----+
	 */

	public byte src;
	public byte flags;
	public int srcoff;
	public long object;
	public long trgoff;

	/* My private one.*/
	private long size = 4;
	private int dstOffset[];

    public LXFixupRecordTable(BinaryReader reader, long offsetBase) throws IOException {
	src = reader.readNextByte();
	flags = reader.readNextByte();
	srcoff = reader.readNextUnsignedShort();
    	
    	/* 
    	 * Source type.
    	 * Supporting:
    	 * 05h = 16-bit Offset fixup (16-bits).
    	 * 06h = 16:32 Pointer fixup (48-bits).
         * 07h = 32-bit Offset fixup (32-bits).
         * 08h = 32-bit Self-relative offset fixup
         * 20h = Source List Flag.
         * 
         * XXX:
         * 02h = 16-bit Selector fixup (16-bits).
         * 10h = Fixup to Alias Flag.
		 */
    	switch (getSourceType()) {
    	case 0x02:
    	case 0x05:
    	case 0x06:
    	case 0x07:
    	case 0x08:
    		break;
    	default:
    		throw new UnknownError("Unsupported fixup source: " + getSourceType());
    	}
    	
    	/*
    	 * Supported flags 0x10 and 0x40.
    	 */
    	if ((flags & ~0x50) != 0) {
    		throw new UnknownError("Unsupported target flags: " + flags);
    	}

    	/*
    	 * [Doc]
    	 * 40h = 16-bit Object Number/Module Ordinal Flag.
    	 * When  set,  the   object  number  or  module
    	 * ordinal number  is 16-bits, otherwise  it is
    	 * 8-bits.
    	 */
        if ((flags & 0x40) == 0x40) {
        	object = reader.readNextUnsignedShort();
        	size += 2;
        } else {
        	object = reader.readNextByte();
        	size += 1;
        }
        object -= 1;
    	
        /* 
         * [Doc] [Target offset.]
         * It  is  not  present  when  the
         * Source Type  specifies a 16-bit Selector fixup (02h).
         */
        if (getSourceType() == 0x2) {
        	return;
        }
        
        /*
         * [Doc]
    	 * 10h = 32-bit Target Offset Flag.
         * When  set, the  target  offset  is  32-bits,
         * otherwise it is 16-bits.
         */    
        if ((flags & 0x10) == 0x10) {
        	trgoff = reader.readNextUnsignedInt();
        	size += 4;
        } else {
        	trgoff = reader.readNextUnsignedShort();
        	size += 2;
        }
        
        if ((src & 0x20) == 0x20) {
            this.dstOffset = new int[srcoff];
            for (int i = 0; i < srcoff; i++) {
                srcoff = reader.readNextUnsignedShort();
                this.dstOffset[i] = (int)offsetBase + srcoff;
            }
        } else {
            this.dstOffset = new int[1];
            this.dstOffset[0] = (int)offsetBase + srcoff;
        }
    }
    
    public long getSizeInFile() {
    	return size;
    }
    
    public int getSourceType() {
    	return src & 0xF;
    }
    
    public int getDSTOffsetCount() {
    	return dstOffset.length;
    }
    
    public int getDSTOffset(int index) {
    	return dstOffset[index];
    }
}
