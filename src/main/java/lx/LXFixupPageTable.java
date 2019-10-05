package lx;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

/*
 * [Doc]
 *
 *                  +-----+-----+-----+-----+
 * Logical Page #1  |  OFFSET FOR PAGE #1   |
 *                  +-----+-----+-----+-----+
 * Logical Page #2  |  OFFSET FOR PAGE #2   |
 *                  +-----+-----+-----+-----+
 *                          . . .
 *                  +-----+-----+-----+-----+
 * Logical Page #n  |  OFFSET FOR PAGE #n   |
 *                  +-----+-----+-----+-----+
 *                  |OFF TO END OF FIXUP REC|   This is equal to:
 *                  +-----+-----+-----+-----+   Offset for page #n + Size
 *                                              of fixups for page #n
 */


public class LXFixupPageTable {
	public long offset;
	
	public LXFixupPageTable(BinaryReader reader) throws IOException {
		offset = reader.readNextUnsignedInt();
	}
}