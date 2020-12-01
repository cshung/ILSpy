// Copyright (c) 2018 Siegfried Pammer
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy of this
// software and associated documentation files (the "Software"), to deal in the Software
// without restriction, including without limitation the rights to use, copy, modify, merge,
// publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
// to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or
// substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
// INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
// PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
// FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection.Metadata.Ecma335;

using Iced.Intel;

using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.IL;
using ICSharpCode.Decompiler.Metadata;

using ILCompiler.Reflection.ReadyToRun;
using ILCompiler.Reflection.ReadyToRun.Amd64;

namespace ICSharpCode.ILSpy.ReadyToRun
{
	internal class ReadyToRunDisassembler
	{
		private readonly ITextOutput output;
		private readonly ReadyToRunReader reader;
		private readonly RuntimeFunction runtimeFunction;

		public ReadyToRunDisassembler(ITextOutput output, ReadyToRunReader reader, RuntimeFunction runtimeFunction)
		{
			this.output = output;
			this.reader = reader;
			this.runtimeFunction = runtimeFunction;
		}

		public void Disassemble(PEFile currentFile, int bitness, ulong address, bool showMetadataTokens, bool showMetadataTokensInBase10)
		{
			// TODO: Decorate the disassembly with GCInfo
			ReadyToRunMethod readyToRunMethod = runtimeFunction.Method;
			WriteCommentLine(readyToRunMethod.SignatureString);

			Dictionary<ulong, UnwindCode> unwindInfo = null;
			if (ReadyToRunOptions.GetIsShowUnwindInfo(null) && bitness == 64)
			{
				unwindInfo = WriteUnwindInfo();
			}

			bool isShowDebugInfo = ReadyToRunOptions.GetIsShowDebugInfo(null);
			Dictionary<VarLocType, HashSet<ValueTuple<DebugInfo, NativeVarInfo>>> debugInfo = null;
			if (isShowDebugInfo)
			{
				debugInfo = WriteDebugInfo();
			}

			byte[] codeBytes = new byte[runtimeFunction.Size];
			for (int i = 0; i < runtimeFunction.Size; i++)
			{
				codeBytes[i] = reader.Image[reader.GetOffset(runtimeFunction.StartAddress) + i];
			}

			var codeReader = new ByteArrayCodeReader(codeBytes);
			var decoder = Decoder.Create(bitness, codeReader);
			decoder.IP = address;
			ulong endRip = decoder.IP + (uint)codeBytes.Length;

			var instructions = new InstructionList();
			while (decoder.IP < endRip)
			{
				decoder.Decode(out instructions.AllocUninitializedElement());
			}

			string disassemblyFormat = ReadyToRunOptions.GetDisassemblyFormat(null);
			Formatter formatter = null;
			if (disassemblyFormat.Equals(ReadyToRunOptions.intel))
			{
				formatter = new NasmFormatter();
			}
			else
			{
				Debug.Assert(disassemblyFormat.Equals(ReadyToRunOptions.gas));
				formatter = new GasFormatter();
			}
			formatter.Options.DigitSeparator = "`";
			formatter.Options.FirstOperandCharIndex = 10;
			var tempOutput = new StringOutput();
			ulong baseInstrIP = instructions[0].IP;
			foreach (var instr in instructions)
			{
				int byteBaseIndex = (int)(instr.IP - address);
				if (isShowDebugInfo && runtimeFunction.DebugInfo != null)
				{
					foreach (var bound in runtimeFunction.DebugInfo.BoundsList)
					{
						if (bound.NativeOffset == byteBaseIndex)
						{
							if (bound.ILOffset == (uint)DebugInfoBoundsType.Prolog)
							{
								WriteCommentLine("Prolog");
							}
							else if (bound.ILOffset == (uint)DebugInfoBoundsType.Epilog)
							{
								WriteCommentLine("Epilog");
							}
							else
							{
								WriteCommentLine($"IL_{bound.ILOffset:x4}");
							}
						}
					}
				}
				formatter.Format(instr, tempOutput);
				output.Write(instr.IP.ToString("X16"));
				output.Write(" ");
				int instrLen = instr.Length;
				for (int i = 0; i < instrLen; i++)
				{
					output.Write(codeBytes[byteBaseIndex + i].ToString("X2"));
				}
				int missingBytes = 10 - instrLen;
				for (int i = 0; i < missingBytes; i++)
				{
					output.Write("  ");
				}
				output.Write(" ");
				output.Write(tempOutput.ToStringAndReset());
				DecorateUnwindInfo(unwindInfo, baseInstrIP, instr);
				DecorateDebugInfo(instr, debugInfo, baseInstrIP);
				DecorateCallSite(currentFile, showMetadataTokens, showMetadataTokensInBase10, instr);
			}
			output.WriteLine();
		}

		private void WriteCommentLine(string comment)
		{
			output.WriteLine("; " + comment);
		}

		private Dictionary<VarLocType, HashSet<(DebugInfo debugInfo, NativeVarInfo varLoc)>> WriteDebugInfo()
		{
			Dictionary<VarLocType, HashSet<(DebugInfo debugInfo, NativeVarInfo varLoc)>> debugInfoDict = new Dictionary<VarLocType, HashSet<(DebugInfo debugInfo, NativeVarInfo varLoc)>>();
			IReadOnlyList<RuntimeFunction> runTimeList = runtimeFunction.Method.RuntimeFunctions;
			foreach (RuntimeFunction runtimeFunction in runTimeList)
			{
				DebugInfo debugInfo = runtimeFunction.DebugInfo;
				if (debugInfo != null && debugInfo.BoundsList.Count > 0)
				{
					for (int i = 0; i < debugInfo.VariablesList.Count; ++i)
					{
						var varLoc = debugInfo.VariablesList[i];
						try
						{
							var typeSet = new HashSet<ValueTuple<DebugInfo, NativeVarInfo>>();
							bool found = debugInfoDict.TryGetValue(varLoc.VariableLocation.VarLocType, out typeSet);
							if (found)
							{
								(DebugInfo debugInfo, NativeVarInfo varLoc) newTuple = (debugInfo, varLoc);
								typeSet.Add(newTuple);
							}
							else
							{
								typeSet = new HashSet<ValueTuple<DebugInfo, NativeVarInfo>>();
								debugInfoDict.Add(varLoc.VariableLocation.VarLocType, typeSet);
								(DebugInfo debugInfo, NativeVarInfo varLoc) newTuple = (debugInfo, varLoc);
								typeSet.Add(newTuple);
							}
						}
						catch (ArgumentNullException)
						{
							output.WriteLine("Failed to find hash set of Debug info type");
						}

						if (varLoc.VariableLocation.VarLocType != VarLocType.VLT_REG && varLoc.VariableLocation.VarLocType != VarLocType.VLT_STK
							&& varLoc.VariableLocation.VarLocType != VarLocType.VLT_STK_BYREF)
						{
							output.WriteLine($"    Variable Number: {varLoc.VariableNumber}");
							output.WriteLine($"    Start Offset: 0x{varLoc.StartOffset:X}");
							output.WriteLine($"    End Offset: 0x{varLoc.EndOffset:X}");
							output.WriteLine($"    Loc Type: {varLoc.VariableLocation.VarLocType}");
							switch (varLoc.VariableLocation.VarLocType)
							{
								case VarLocType.VLT_REG:
								case VarLocType.VLT_REG_FP:
								case VarLocType.VLT_REG_BYREF:
									output.WriteLine($"    Register: {DebugInfo.GetPlatformSpecificRegister(debugInfo.Machine, varLoc.VariableLocation.Data1)}");
									break;
								case VarLocType.VLT_STK:
								case VarLocType.VLT_STK_BYREF:
									output.WriteLine($"    Base Register: {DebugInfo.GetPlatformSpecificRegister(debugInfo.Machine, varLoc.VariableLocation.Data1)}");
									output.WriteLine($"    Stack Offset: {varLoc.VariableLocation.Data2}");
									break;
								case VarLocType.VLT_REG_REG:
									output.WriteLine($"    Register 1: {DebugInfo.GetPlatformSpecificRegister(debugInfo.Machine, varLoc.VariableLocation.Data1)}");
									output.WriteLine($"    Register 2: {DebugInfo.GetPlatformSpecificRegister(debugInfo.Machine, varLoc.VariableLocation.Data2)}");
									break;
								case VarLocType.VLT_REG_STK:
									output.WriteLine($"    Register: {DebugInfo.GetPlatformSpecificRegister(debugInfo.Machine, varLoc.VariableLocation.Data1)}");
									output.WriteLine($"    Base Register: {DebugInfo.GetPlatformSpecificRegister(debugInfo.Machine, varLoc.VariableLocation.Data2)}");
									output.WriteLine($"    Stack Offset: {varLoc.VariableLocation.Data3}");
									break;
								case VarLocType.VLT_STK_REG:
									output.WriteLine($"    Stack Offset: {varLoc.VariableLocation.Data1}");
									output.WriteLine($"    Base Register: {DebugInfo.GetPlatformSpecificRegister(debugInfo.Machine, varLoc.VariableLocation.Data2)}");
									output.WriteLine($"    Register: {DebugInfo.GetPlatformSpecificRegister(debugInfo.Machine, varLoc.VariableLocation.Data3)}");
									break;
								case VarLocType.VLT_STK2:
									output.WriteLine($"    Base Register: {DebugInfo.GetPlatformSpecificRegister(debugInfo.Machine, varLoc.VariableLocation.Data1)}");
									output.WriteLine($"    Stack Offset: {varLoc.VariableLocation.Data2}");
									break;
								case VarLocType.VLT_FPSTK:
									output.WriteLine($"    Offset: {DebugInfo.GetPlatformSpecificRegister(debugInfo.Machine, varLoc.VariableLocation.Data1)}");
									break;
								case VarLocType.VLT_FIXED_VA:
									output.WriteLine($"    Offset: {DebugInfo.GetPlatformSpecificRegister(debugInfo.Machine, varLoc.VariableLocation.Data1)}");
									break;
								default:
									output.WriteLine("WRN: Unexpected variable location type");
									break;
							}
							output.WriteLine("");
						}
					}
				}
			}
			return debugInfoDict;
		}

		private Dictionary<ulong, UnwindCode> WriteUnwindInfo()
		{
			Dictionary<ulong, UnwindCode> unwindCodes = new Dictionary<ulong, UnwindCode>();
			if (runtimeFunction.UnwindInfo is UnwindInfo amd64UnwindInfo)
			{
				string parsedFlags = "";
				if ((amd64UnwindInfo.Flags & (int)UnwindFlags.UNW_FLAG_EHANDLER) != 0)
				{
					parsedFlags += " EHANDLER";
				}
				if ((amd64UnwindInfo.Flags & (int)UnwindFlags.UNW_FLAG_UHANDLER) != 0)
				{
					parsedFlags += " UHANDLER";
				}
				if ((amd64UnwindInfo.Flags & (int)UnwindFlags.UNW_FLAG_CHAININFO) != 0)
				{
					parsedFlags += " CHAININFO";
				}
				if (parsedFlags.Length == 0)
				{
					parsedFlags = " NHANDLER";
				}
				WriteCommentLine($"UnwindInfo:");
				WriteCommentLine($"Version:            {amd64UnwindInfo.Version}");
				WriteCommentLine($"Flags:              0x{amd64UnwindInfo.Flags:X2}{parsedFlags}");
				WriteCommentLine($"FrameRegister:      {((amd64UnwindInfo.FrameRegister == 0) ? "none" : amd64UnwindInfo.FrameRegister.ToString().ToLower())}");
				for (int unwindCodeIndex = 0; unwindCodeIndex < amd64UnwindInfo.UnwindCodes.Count; unwindCodeIndex++)
				{
					unwindCodes.Add((ulong)(amd64UnwindInfo.UnwindCodes[unwindCodeIndex].CodeOffset), amd64UnwindInfo.UnwindCodes[unwindCodeIndex]);
				}
			}
			return unwindCodes;
		}

		private void DecorateUnwindInfo(Dictionary<ulong, UnwindCode> unwindInfo, ulong baseInstrIP, Instruction instr)
		{
			ulong nextInstructionOffset = instr.NextIP - baseInstrIP;
			if (unwindInfo != null && unwindInfo.ContainsKey(nextInstructionOffset))
			{
				UnwindCode unwindCode = unwindInfo[nextInstructionOffset];
				output.Write($" ; {unwindCode.UnwindOp}({unwindCode.OpInfoStr})");
			}
		}

		private void DecorateDebugInfo(Instruction instr, Dictionary<VarLocType, HashSet<(DebugInfo debugInfo, NativeVarInfo varLoc)>> debugInfoDict, ulong baseInstrIP)
		{
			if (debugInfoDict != null)
			{
				InstructionInfoFactory factory = new InstructionInfoFactory();
				InstructionInfo info = factory.GetInfo(instr);
				HashSet<ValueTuple<DebugInfo, NativeVarInfo>> stkSet = new HashSet<ValueTuple<DebugInfo, NativeVarInfo>>();
				if (debugInfoDict.ContainsKey(VarLocType.VLT_STK))
				{
					stkSet.UnionWith(debugInfoDict[VarLocType.VLT_STK]);
				}
				if (debugInfoDict.ContainsKey(VarLocType.VLT_STK_BYREF))
				{
					stkSet.UnionWith(debugInfoDict[VarLocType.VLT_STK_BYREF]);
				}
				if (stkSet != null)
				{
					foreach (UsedMemory usedMemInfo in info.GetUsedMemory())
					{ //for each time a [register +- value] is used
						foreach ((DebugInfo debugInfo, NativeVarInfo varLoc) tuple in stkSet)
						{ //for each VLT_STK variable
							var debugInfo = tuple.debugInfo;
							var varInfo = tuple.varLoc;
							int stackOffset = varInfo.VariableLocation.Data2;
							ulong adjOffset;
							bool negativeOffset;
							if (stackOffset < 0)
							{
								int absValue = -1 * stackOffset;
								adjOffset = ulong.MaxValue - (ulong)absValue + 1;
								negativeOffset = true;
							}
							else
							{
								adjOffset = (ulong)stackOffset;
								negativeOffset = false;
							}
							if (varInfo.StartOffset < instr.IP - baseInstrIP && varInfo.EndOffset > instr.IP - baseInstrIP &&
								DebugInfo.GetPlatformSpecificRegister(debugInfo.Machine, varInfo.VariableLocation.Data1) == usedMemInfo.Base.ToString() &&
								adjOffset == usedMemInfo.Displacement)
							{
								output.Write($"; [{usedMemInfo.Base.ToString().ToLower()}{(negativeOffset ? '-' : '+')}{Math.Abs(stackOffset):X}h] = {varInfo.Variable.Type} {varInfo.Variable.Index}");
							}
						}
					}
				}
				HashSet<ValueTuple<DebugInfo, NativeVarInfo>> regSet = new HashSet<ValueTuple<DebugInfo, NativeVarInfo>>();
				if (debugInfoDict.ContainsKey(VarLocType.VLT_REG))
				{
					regSet.UnionWith(debugInfoDict[VarLocType.VLT_REG]);
				}
				if (debugInfoDict.ContainsKey(VarLocType.VLT_REG_BYREF))
				{
					regSet.UnionWith(debugInfoDict[VarLocType.VLT_REG_BYREF]);
				}
				if (debugInfoDict.ContainsKey(VarLocType.VLT_REG_FP))
				{
					regSet.UnionWith(debugInfoDict[VarLocType.VLT_REG_FP]);
				}
				if (regSet != null)
				{
					foreach (UsedRegister usedMemInfo in info.GetUsedRegisters())
					{
						foreach ((DebugInfo debugInfo, NativeVarInfo varLoc) tuple in regSet)
						{
							var debugInfo = tuple.debugInfo;
							var varInfo = tuple.varLoc;
							if (varInfo.StartOffset <= (instr.IP - baseInstrIP) && (instr.IP - baseInstrIP) < varInfo.EndOffset &&
								DebugInfo.GetPlatformSpecificRegister(debugInfo.Machine, varInfo.VariableLocation.Data1) == usedMemInfo.Register.ToString())
							{
								output.Write($"; {usedMemInfo.Register.ToString().ToLower()} = {varInfo.Variable.Type} {varInfo.Variable.Index}");
							}
						}
					}
				}
			}
		}

		private void DecorateCallSite(PEFile currentFile, bool showMetadataTokens, bool showMetadataTokensInBase10, Instruction instr)
		{
			if (instr.IsCallNearIndirect)
			{
				int importCellAddress = (int)instr.IPRelativeMemoryAddress;
				if (reader.ImportSignatures.ContainsKey(importCellAddress))
				{
					output.Write(" ; ");
					ReadyToRunSignature signature = reader.ImportSignatures[importCellAddress];
					switch (signature)
					{
						case MethodDefEntrySignature methodDefSignature:
							var methodDefToken = MetadataTokens.EntityHandle(unchecked((int)methodDefSignature.MethodDefToken));
							if (showMetadataTokens)
							{
								if (showMetadataTokensInBase10)
								{
									output.WriteReference(currentFile, methodDefToken, $"({MetadataTokens.GetToken(methodDefToken)}) ", "metadata");
								}
								else
								{
									output.WriteReference(currentFile, methodDefToken, $"({MetadataTokens.GetToken(methodDefToken):X8}) ", "metadata");
								}
							}
							methodDefToken.WriteTo(currentFile, output, Decompiler.Metadata.GenericContext.Empty);
							break;
						case MethodRefEntrySignature methodRefSignature:
							var methodRefToken = MetadataTokens.EntityHandle(unchecked((int)methodRefSignature.MethodRefToken));
							if (showMetadataTokens)
							{
								if (showMetadataTokensInBase10)
								{
									output.WriteReference(currentFile, methodRefToken, $"({MetadataTokens.GetToken(methodRefToken)}) ", "metadata");
								}
								else
								{
									output.WriteReference(currentFile, methodRefToken, $"({MetadataTokens.GetToken(methodRefToken):X8}) ", "metadata");
								}
							}
							methodRefToken.WriteTo(currentFile, output, Decompiler.Metadata.GenericContext.Empty);
							break;
						default:
							output.WriteLine(reader.ImportSignatures[importCellAddress].ToString(new SignatureFormattingOptions()));
							break;
					}
					output.WriteLine();
				}
			}
			else
			{
				output.WriteLine();
			}
		}
	}
}
