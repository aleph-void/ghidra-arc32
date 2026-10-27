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

import java.math.BigInteger;
import java.util.*;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.SymbolicPropogator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Zero-overhead loops set up with SR instead of LP (legacy ARC, ARCtangent-A4).
 * <p>
 * The LP instruction marks its loop end through context while it is disassembled. A loop can
 * also be set up by writing LP_START and LP_END (auxiliary registers 2 and 3) with SR; GCC uses
 * this for single-instruction loops (multi-bit shifts on cores without a barrel shifter):
 * <pre>
 *   mov  r4,loop&gt;&gt;2 ; sr r4,[lp_start] ; add r4,r4,1 ; sr r4,[lp_end] ; nop ; nop
 * loop: lsr r2,r2          ; executed LP_COUNT times
 * </pre>
 * This analyzer finds SR writes of LP_END whose value constant propagation can determine,
 * pairs each with the preceding LP_START write of the same function, and sets the loopEnd and
 * loopStart context at the loop end, as LP does, so that the instruction there branches back to
 * the loop start while LP_COUNT is not exhausted.
 */
public class Arc32LoopAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "ARC32 SR Zero-Overhead Loops";
	private static final String DESCRIPTION =
		"Marks the loop end of zero-overhead loops set up with SR to LP_START/LP_END " +
			"(constant addresses), so that the loop is visible to analysis and the decompiler.";

	public Arc32LoopAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().toString().equals("ARC32");
	}

	/** Auxiliary register written by an SR with a short-immediate register number, or -1. */
	private static int srAux(Program program, Instruction in) {
		try {
			if (in.getLength() < 4) {
				return -1;
			}
			int w = program.getMemory().getInt(in.getAddress(), program.getLanguage().isBigEndian());
			int major = (w >>> 27) & 0x1f;
			int a = (w >>> 21) & 0x3f;
			int b = (w >>> 15) & 0x3f;
			if (major != 2 || (a & 0x10) == 0 || (b != 61 && b != 63)) {
				return -1;
			}
			return ((w << 23) >> 23);
		}
		catch (MemoryAccessException e) {
			return -1;
		}
	}

	/** Value stored by an SR (C field: register, short immediate or long immediate), or null. */
	private static Long srValue(Program program, Instruction in, SymbolicPropogator prop) {
		try {
			boolean be = program.getLanguage().isBigEndian();
			int w = program.getMemory().getInt(in.getAddress(), be);
			int c = (w >>> 9) & 0x3f;
			if (c == 61 || c == 63) {
				return (long) ((w << 23) >> 23);
			}
			if (c == 62) {
				return program.getMemory().getInt(in.getAddress().add(4), be) & 0xffffffffL;
			}
			Register r = program.getLanguage().getRegister(c == 26 ? "gp" : c == 27 ? "fp"
					: c == 28 ? "sp" : c == 29 ? "ilink1" : c == 30 ? "ilink2" : c == 31 ? "blink"
							: c == 60 ? "lp_count" : "r" + c);
			if (r == null || prop == null) {
				return null;
			}
			SymbolicPropogator.Value v = prop.getRegisterValue(in.getAddress(), r);
			if (v == null || v.isRegisterRelativeValue()) {
				return null;
			}
			return v.getValue();
		}
		catch (MemoryAccessException e) {
			return null;
		}
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		Listing listing = program.getListing();
		Map<Function, List<Instruction>> byFunction = new LinkedHashMap<>();
		for (Instruction in : listing.getInstructions(set, true)) {
			monitor.checkCancelled();
			if (!in.getMnemonicString().equals("sr") || srAux(program, in) != 3) {
				continue;
			}
			Function f = program.getFunctionManager().getFunctionContaining(in.getAddress());
			byFunction.computeIfAbsent(f, k -> new ArrayList<>()).add(in);
		}
		Register loopEnd = program.getRegister("loopEnd");
		Register loopStart = program.getRegister("loopStart");
		ProgramContext ctx = program.getProgramContext();
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		for (Map.Entry<Function, List<Instruction>> e : byFunction.entrySet()) {
			Function f = e.getKey();
			for (Instruction sr : e.getValue()) {
				// propagate constants through the function, or (outside a function) through the
				// straight-line code that leads to the SR
				SymbolicPropogator prop = new SymbolicPropogator(program);
				AddressSetView body;
				Address from;
				if (f != null) {
					body = f.getBody();
					from = f.getEntryPoint();
				}
				else {
					Instruction q = sr;
					for (int i = 0; i < 64; i++) {
						Instruction prev = q.getPrevious();
						if (prev == null || prev.getFallThrough() == null ||
							!prev.getFallThrough().equals(q.getAddress())) {
							break;
						}
						q = prev;
					}
					from = q.getAddress();
					body = new AddressSet(from, sr.getMaxAddress());
				}
				prop.flowConstants(from, body, new ConstantPropagationContextEvaluator(monitor, true),
					true, monitor);
				Long end = srValue(program, sr, prop);
				// the closest preceding write of LP_START in the same function (or block of code)
				Long start = null;
				Instruction p = sr.getPrevious();
				for (int i = 0; p != null && i < 64 && body.contains(p.getAddress()); i++, p = p.getPrevious()) {
					if (p.getMnemonicString().equals("sr") && srAux(program, p) == 2) {
						start = srValue(program, p, prop);
						break;
					}
				}
				if (end == null || start == null) {
					log.appendMsg(NAME, "loop at " + sr.getAddress() +
						": LP_END/LP_START value not constant, loop end not marked");
					continue;
				}
				Address endAddr = space.getAddress((end & 0xffffffL) << 2);
				try {
					ctx.setValue(loopEnd, endAddr, endAddr, BigInteger.ONE);
					ctx.setValue(loopStart, endAddr, endAddr, BigInteger.valueOf(start & 0xffffffL));
				}
				catch (ghidra.program.model.listing.ContextChangeException ex) {
					log.appendMsg(NAME, "cannot set loop context at " + endAddr + ": " + ex.getMessage());
					continue;
				}
				Instruction at = listing.getInstructionAt(endAddr);
				if (at != null) {
					listing.clearCodeUnits(endAddr, endAddr, false);
				}
				new DisassembleCommand(new AddressSet(endAddr), null, false).applyTo(program, monitor);
			}
		}
		return true;
	}
}
