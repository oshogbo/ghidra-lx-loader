// Post-import assertions for the ghidra-lx-loader smoke test.
// Runs under analyzeHeadless.
// @category Testing

import java.io.FileWriter;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;

public class SmokeAssertions extends GhidraScript {

	private String resultFile;

	@Override
	public void run() throws Exception {
		resultFile = System.getenv("LX_SMOKE_RESULT_FILE");
		try {
			check();
		}
		catch (AssertionError e) {
			writeResult("FAIL", e.getMessage());
			printerr("SMOKE FAIL: " + e.getMessage());
			throw e;
		}
	}

	private void check() throws Exception {
		if (currentProgram == null) {
			fail("no current program after import");
		}

		String fmt = currentProgram.getOptions("Program Information")
				.getString("Executable Format", "");
		if (!fmt.contains("Linear eXecutable")) {
			fail("unexpected loader: " + fmt);
		}

		List<String> cseg = new ArrayList<>();
		List<String> dseg = new ArrayList<>();
		for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
			String name = b.getName();
			if (name.startsWith("cseg")) {
				cseg.add(name);
			}
			else if (name.startsWith("dseg")) {
				dseg.add(name);
			}
		}
		if (cseg.isEmpty()) {
			fail("no cseg* memory blocks were created");
		}

		// Modules whose LE header has EIP object # == 0 (VxDs, most DLLs)
		// legitimately have no entry point; only verify disassembly when
		// the loader registered one.
		AddressIterator it =
			currentProgram.getSymbolTable().getExternalEntryPointIterator();
		Address entry = it.hasNext() ? it.next() : null;

		Instruction instr = null;
		String entryDesc;
		if (entry == null) {
			entryDesc = "entry=none";
		}
		else {
			instr = currentProgram.getListing().getInstructionAt(entry);
			if (instr == null) {
				fail("entry point " + entry + " did not disassemble");
			}
			entryDesc = String.format("entry=%s; first_instr=%s", entry, instr);
		}

		writeFacts(fmt, entry, instr);

		String msg = String.format(
			"loader=%s; cseg=%d; dseg=%d; %s",
			fmt, cseg.size(), dseg.size(), entryDesc);
		writeResult("OK", msg);
		println("SMOKE OK: " + msg);
	}

	private void fail(String msg) {
		throw new AssertionError(msg);
	}

	// Deterministic per-binary facts for the corpus regression test
	// (tests/corpus.sh): chosen loader, every memory block with a hash
	// of its post-fixup contents, and the entry point. Written only
	// when LX_SMOKE_FACTS_FILE is set.
	private void writeFacts(String fmt, Address entry, Instruction instr)
			throws Exception {
		String factsFile = System.getenv("LX_SMOKE_FACTS_FILE");
		if (factsFile == null) {
			return;
		}

		try (PrintWriter w = new PrintWriter(new FileWriter(factsFile))) {
			w.print("loader=" + fmt + "\n");
			for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
				byte[] data = new byte[(int) b.getSize()];
				b.getBytes(b.getStart(), data);
				String perms = (b.isRead() ? "r" : "-") +
					(b.isWrite() ? "w" : "-") +
					(b.isExecute() ? "x" : "-");
				w.print(String.format("block=%s start=%s size=0x%x perms=%s sha256=%s\n",
					b.getName(), b.getStart(), b.getSize(), perms,
					sha256(data)));
			}
			if (entry == null) {
				w.print("entry=none\n");
			}
			else {
				w.print(String.format("entry=%s instr=%s\n", entry, instr));
			}
		}
	}

	private String sha256(byte[] data) throws Exception {
		StringBuilder sb = new StringBuilder();
		for (byte b : MessageDigest.getInstance("SHA-256").digest(data)) {
			sb.append(String.format("%02x", b));
		}
		return sb.toString();
	}

	private void writeResult(String status, String msg) {
		if (resultFile == null) {
			return;
		}
		try (PrintWriter w = new PrintWriter(new FileWriter(resultFile))) {
			w.println(status);
			w.println(msg);
		}
		catch (Exception e) {
			// best effort
		}
	}
}
