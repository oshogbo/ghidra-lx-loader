// Post-import assertions for the ghidra-lx-loader smoke test.
// Runs under analyzeHeadless.
// @category Testing

import java.io.FileWriter;
import java.io.PrintWriter;
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

		String entryDesc;
		if (entry == null) {
			entryDesc = "entry=none";
		}
		else {
			Instruction instr = currentProgram.getListing().getInstructionAt(entry);
			if (instr == null) {
				fail("entry point " + entry + " did not disassemble");
			}
			entryDesc = String.format("entry=%s; first_instr=%s", entry, instr);
		}

		String msg = String.format(
			"loader=%s; cseg=%d; dseg=%d; %s",
			fmt, cseg.size(), dseg.size(), entryDesc);
		writeResult("OK", msg);
		println("SMOKE OK: " + msg);
	}

	private void fail(String msg) {
		throw new AssertionError(msg);
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
