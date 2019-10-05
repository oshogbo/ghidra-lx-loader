package lx;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

public class LXFixupRecordTable {
	/*
	 *         +-----+-----+-----+-----+
     *     00h | SRC |FLAGS|SRCOFF/CNT*|
     *		   +-----+-----+-----+-----+-----+-----+
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
	private int dstOffset;
	
    public LXFixupRecordTable(BinaryReader reader, long offsetBase) throws IOException {
    	src = reader.readNextByte();
    	flags = reader.readNextByte();
    	srcoff = reader.readNextUnsignedShort();
    	this.dstOffset = (int)offsetBase + srcoff;
    	
    	/* 
    	 * Source type.
    	 * Supporting:
    	 * 05h = 16-bit Offset fixup (16-bits).
         * 07h = 32-bit Offset fixup (32-bits).
         * 
         * 
         * XXX:
         * 02h = 16-bit Selector fixup (16-bits).
         * 10h = Fixup to Alias Flag.
    	 */
    	if ((src & ~0x1F) != 0) {	
    		throw new UnknownError("Unsupported fixup type");
    	}
    	
    	switch (getSourceType()) {
    	case 0x02:
    	case 0x05:
    	case 0x07:
    		break;
    	default:
    		throw new UnknownError("Unsupported fixup source");
    	}
    	
    	/*
    	 * Supported flags 0x10 and 0x40.
    	 */
    	if ((flags & ~0x50) != 0) {
    		throw new UnknownError("Unsupported target flags");
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
    }
    
    public long getSizeInFile() {
    	return size;
    }
    
    public int getSourceType() {
    	return src & 0xF;
    }
    
    public int getDSTOffset() {
    	return dstOffset;
    }
}
