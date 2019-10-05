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