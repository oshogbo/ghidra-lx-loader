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
	public int srcoff_count;
	public long object;		/* Internal reference: 0-based object number. */
	public long trgoff;
	public long module;		/* Imports: 0-based import module name table index. */
	public long import_ordinal;	/* Import by ordinal: imported procedure ordinal. */
	public long name_offset;	/* Import by name: import procedure name table offset. */
	public long entry_ordinal;	/* Internal via entry table: 1-based entry ordinal. */
	public long additive;		/* Additive value, 0 when absent. */
	public long import_addr;	/* Import slot address, assigned by LX. */

	/* My private one.*/
	private long size = 4;
	private int dstOffset[];

    public LXFixupRecordTable(BinaryReader reader, long offsetBase) throws IOException {
	src = reader.readNextByte();
	flags = reader.readNextByte();

	/*
	 * [Doc]
	 * 20h = Source List flag.
	 *
	 * When  the  'Source  List'  Flag is set,  the
	 * SRCOFF field  is compressed  to  a byte  and
	 * contains the number of source offsets.
	 */
	if ((src & 0x20) == 0x20) {
		srcoff_count = reader.readNextUnsignedByte();
		size += 1;
	} else {
		/*
		 * [Doc]
		 * Source offsets are SIGNED (exe_vxd.h: short r32_soff):
		 * a fixup crossing a page boundary gets a second record on
		 * the next page with a negative offset back into the
		 * preceding page (docs/lxexe.txt, note under SRCOFF).
		 */
		srcoff_count = reader.readNextShort();
		size += 2;
	}
    	
    	/* 
    	 * Source type. Full table (cross-checked against Open Watcom's
    	 * DOS/32A loader fix_tab in contrib/extender/dos32a/src/dos32a/
    	 * loader.asm):
    	 *   00h = Byte fixup (8-bits)            -- not yet supported
    	 *   01h = (invalid / reserved)
    	 *   02h = 16-bit Selector fixup (16-bits)
    	 *   03h = 16:16 Pointer fixup (32-bits)
    	 *   04h = (invalid / reserved)
    	 *   05h = 16-bit Offset fixup (16-bits)
    	 *   06h = 16:32 Pointer fixup (48-bits)
    	 *   07h = 32-bit Offset fixup (32-bits)
    	 *   08h = 32-bit Self-relative offset fixup
    	 *   20h = Source List flag (modifies SRCOFF encoding, see above)
    	 *
    	 * XXX:
    	 *   10h = Fixup to Alias flag (not yet handled).
		 */
    	switch (getSourceType()) {
    	case 0x02:
    	case 0x03:
    	case 0x05:
    	case 0x06:
    	case 0x07:
    	case 0x08:
    		break;
    	default:
    		throw new UnknownError("Unsupported fixup source: " + getSourceType());
    	}
    	
    	/*
    	 * [Doc] Target Flags:
    	 *   03h = Target type mask:
    	 *         00h = Internal reference.
    	 *         01h = Imported reference by ordinal.
    	 *         02h = Imported reference by name.
    	 *         03h = Internal reference via entry table.
    	 *   04h = Additive Fixup Flag.
    	 *   08h = Internal Chaining Fixup Flag  -- not supported.
    	 *   10h = 32-bit Target Offset Flag.
    	 *   20h = 32-bit Additive Fixup Flag.
    	 *   40h = 16-bit Object Number/Module Ordinal Flag.
    	 *   80h = 8-bit Ordinal Flag.
    	 */
    	if ((flags & 0x08) != 0) {
    		throw new UnknownError(String.format("Unsupported target flags: 0x%02x",
    		    flags & 0xFF));
    	}

    	/*
    	 * [Doc]
    	 * 40h = 16-bit Object Number/Module Ordinal Flag.
    	 * When  set,  the   object  number  or  module
    	 * ordinal number  is 16-bits, otherwise  it is
    	 * 8-bits. Both are 1-based.
    	 */
    	long ord;
        if ((flags & 0x40) == 0x40) {
        	ord = reader.readNextUnsignedShort();
        	size += 2;
        } else {
        	ord = reader.readNextUnsignedByte();
        	size += 1;
        }

        switch (getTargetType()) {
        case 0x00: /* Internal reference. */
        	object = ord - 1;

	        /*
	         * [Doc] [Target offset.]
	         * It  is  not  present  when  the
	         * Source Type  specifies a 16-bit Selector fixup (02h).
	         *
	         * 10h = 32-bit Target Offset Flag.
	         * When  set, the  target  offset  is  32-bits,
	         * otherwise it is 16-bits.
	         */
	        if (getSourceType() != 0x2) {
	        	if ((flags & 0x10) == 0x10) {
	        		trgoff = reader.readNextUnsignedInt();
	        		size += 4;
	        	} else {
	        		trgoff = reader.readNextUnsignedShort();
	        		size += 2;
	        	}
	        }
	        break;
        case 0x01: /* Imported reference by ordinal. */
        	module = ord - 1;

        	/*
        	 * [Doc]
        	 * 80h = 8-bit Ordinal Flag.
        	 * When set,  the ordinal number is 8-bits; otherwise
        	 * it is 16-bits, or 32-bits when the 32-bit Target
        	 * Offset Flag (10h) is set.
        	 */
        	if ((flags & 0x80) == 0x80) {
        		import_ordinal = reader.readNextUnsignedByte();
        		size += 1;
        	} else if ((flags & 0x10) == 0x10) {
        		import_ordinal = reader.readNextUnsignedInt();
        		size += 4;
        	} else {
        		import_ordinal = reader.readNextUnsignedShort();
        		size += 2;
        	}
        	break;
        case 0x02: /* Imported reference by name. */
        	module = ord - 1;

        	/*
        	 * [Doc]
        	 * Offset into the import procedure name table;
        	 * 32-bits when the 32-bit Target Offset Flag (10h)
        	 * is set, otherwise 16-bits.
        	 */
        	if ((flags & 0x10) == 0x10) {
        		name_offset = reader.readNextUnsignedInt();
        		size += 4;
        	} else {
        		name_offset = reader.readNextUnsignedShort();
        		size += 2;
        	}
        	break;
        case 0x03: /* Internal reference via entry table. */
        	entry_ordinal = ord;
        	break;
        }

        /*
         * [Doc]
         * 04h = Additive Fixup Flag.
         * When set, an additive value trails the target data;
         * 32-bits when the 32-bit Additive Flag (20h) is set,
         * otherwise 16-bits.
         */
        if ((flags & 0x04) == 0x04) {
        	if ((flags & 0x20) == 0x20) {
        		additive = reader.readNextUnsignedInt();
        		size += 4;
        	} else {
        		additive = reader.readNextUnsignedShort();
        		size += 2;
        	}
        }

        /*
    	 * [Doc]
         * 20h = When  the  'Source  List'  Flag is set,  the
         * SRCOFF field contains the number of source offsets, and a
         * list  of source  offsets  follows the end of
         * fixup  record (after  the  optional additive
         * value).
         */
        if ((src & 0x20) == 0x20) {
            this.dstOffset = new int[srcoff_count];
            for (int i = 0; i < srcoff_count; i++) {
                int offset = reader.readNextShort(); /* Signed, see SRCOFF above. */
                this.dstOffset[i] = (int)offsetBase + offset;
            }
        } else {
            this.dstOffset = new int[1];
            this.dstOffset[0] = (int)offsetBase + srcoff_count;
        }
    }
    
    public long getSizeInFile() {
    	return size;
    }
    
    public int getSourceType() {
    	return src & 0xF;
    }

    public int getTargetType() {
    	return flags & 0x3;
    }
    
    public int getDSTOffsetCount() {
    	return dstOffset.length;
    }
    
    public int getDSTOffset(int index) {
    	return dstOffset[index];
    }
}
