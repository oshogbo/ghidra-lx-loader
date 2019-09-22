package lx;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

/*
 * XXX: WTF???? This dosen't seem right. 
 *        63                     32 31       16 15         0
 *         +-----+-----+-----+-----+-----+-----+-----+-----+
 *     00h |    PAGE DATA OFFSET   | DATA SIZE |   FLAGS   |
 *         +-----+-----+-----+-----+-----+-----+-----+-----+
 * More reliable looks:
 * 		   32                     16           8           0
 *         +-----+-----+-----+-----+-----+-----+-----+-----+
 *     00h |    PAGE DATA OFFSET   | DATA SIZE |   FLAGS   |
 *         +-----+-----+-----+-----+-----+-----+-----+-----+
 */
public class LXObjectPageTable {
	public long page_data_offset;
	public int data_size;
	public int flags;
	
	public LXObjectPageTable(BinaryReader reader) throws IOException {
		page_data_offset = reader.readNextShort();
		data_size = reader.readNextUnsignedByte();
		flags = reader.readNextUnsignedByte();
		if (flags > 4) {
			throw new UnknownError("Wrong flags" + Integer.toString(flags));
		}
	}
}
