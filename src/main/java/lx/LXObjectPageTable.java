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
