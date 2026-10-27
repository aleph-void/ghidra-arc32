/* ###
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
package arc32;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Indirect calls written as jumps (legacy ARC, GCC 4.5):
 * <pre>
 *   lr   blink,[status]       ; blink = address of the next instruction (STATUS format)
 *   j.d  [r6]                 ; jump through a register ...
 *   add  blink,blink,2        ; ... and, in the delay slot, link past the delay slot
 * </pre>
 * The jump is a call that returns to the instruction after the delay slot. This analyzer marks
 * such jumps with a CALL flow override, so that the code after them is disassembled and the
 * decompiler sees a call.
 */
public class Arc32IndirectCallAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "ARC32 Indirect Calls";
	private static final String DESCRIPTION =
		"Marks j.d [reg] whose delay slot is \"add blink,blink,2\" (a call through a register, " +
			"as GCC writes it) as a call, and disassembles the code it returns to.";

	public Arc32IndirectCallAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.DISASSEMBLY.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().toString().equals("ARC32");
	}

	private static int word(Program program, Address a) throws MemoryAccessException {
		return program.getMemory().getInt(a, program.getLanguage().isBigEndian());
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		Listing listing = program.getListing();
		AddressSet todo = new AddressSet();
		for (Instruction in : listing.getInstructions(set, true)) {
			monitor.checkCancelled();
			if (in.getFlowOverride() == FlowOverride.CALL || in.getLength() != 4) {
				continue;
			}
			try {
				int w = word(program, in.getAddress());
				int major = (w >>> 27) & 0x1f;
				int b = (w >>> 15) & 0x3f;
				int nul = (w >>> 5) & 3;
				// j (bit 9 clear), register target (not an immediate), D delay mode
				if (major != 7 || ((w >>> 9) & 1) != 0 || b >= 61 || nul != 1) {
					continue;
				}
				// delay slot: add blink,blink,2 (A = B = 31, C = 61/63 short immediate, D = 2)
				Address ds = in.getAddress().add(4);
				int d = word(program, ds);
				if (((d >>> 27) & 0x1f) != 8 || ((d >>> 21) & 0x3f) != 31 ||
					((d >>> 15) & 0x3f) != 31 || (((d >>> 9) & 0x3f) | 2) != 63 ||
					((d << 23) >> 23) != 2) {
					continue;
				}
				in.setFlowOverride(FlowOverride.CALL);
				todo.add(ds.add(4));
			}
			catch (MemoryAccessException | AddressOutOfBoundsException e) {
				continue;
			}
		}
		if (!todo.isEmpty()) {
			new DisassembleCommand(todo, null, true).applyTo(program, monitor);
		}
		return true;
	}
}
