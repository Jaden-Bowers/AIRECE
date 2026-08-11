// Deterministic headless export for the AIRECE AI-utility benchmark.

import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;

public class AireceBenchmarkExport extends GhidraScript {
    private static final class CallRecord {
        String site;
        String target;
        String name;
        String kind;
    }

    private static String quote(String value) {
        if (value == null) return "null";
        StringBuilder result = new StringBuilder("\"");
        for (int index = 0; index < value.length(); ++index) {
            char ch = value.charAt(index);
            switch (ch) {
            case '\"': result.append("\\\""); break;
            case '\\': result.append("\\\\"); break;
            case '\b': result.append("\\b"); break;
            case '\f': result.append("\\f"); break;
            case '\n': result.append("\\n"); break;
            case '\r': result.append("\\r"); break;
            case '\t': result.append("\\t"); break;
            default:
                if (ch < 0x20) result.append(String.format("\\u%04x", (int)ch));
                else result.append(ch);
            }
        }
        return result.append('\"').toString();
    }

    private static String hex(Address address) {
        return address == null ? null : String.format("0x%x", address.getOffset());
    }

    private static String byteString(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte value : bytes) result.append(String.format("%02x", value & 0xff));
        return result.toString();
    }

    private String symbolName(Address address) {
        Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(address);
        return symbol == null ? null : symbol.getName(true);
    }

    private List<CallRecord> calls(Function function) {
        List<CallRecord> records = new ArrayList<>();
        InstructionIterator instructions = currentProgram.getListing().getInstructions(
            function.getBody(), true);
        while (instructions.hasNext() && !monitor.isCancelled()) {
            Instruction instruction = instructions.next();
            for (Reference reference : instruction.getReferencesFrom()) {
                if (!reference.getReferenceType().isCall()) continue;
                CallRecord record = new CallRecord();
                record.site = hex(instruction.getAddress());
                record.target = hex(reference.getToAddress());
                record.name = symbolName(reference.getToAddress());
                record.kind = reference.getReferenceType().toString();
                records.add(record);
            }
        }
        Collections.sort(records, Comparator.comparing(item -> item.site));
        return records;
    }

    private String decompile(DecompInterface decompiler, Function function,
                             int timeoutSeconds) {
        try {
            DecompileResults results = decompiler.decompileFunction(
                function, timeoutSeconds, monitor);
            if (!results.decompileCompleted() || results.getDecompiledFunction() == null) {
                return null;
            }
            return results.getDecompiledFunction().getC();
        } catch (Exception error) {
            return null;
        }
    }

    private void writeFunction(PrintWriter out, Function function,
                               DecompInterface decompiler, int timeoutSeconds,
                               int maxInstructions, int maxDecompileChars) {
        String decompiled = decompile(decompiler, function, timeoutSeconds);
        boolean decompileTruncated = decompiled != null &&
            decompiled.length() > maxDecompileChars;
        if (decompileTruncated) decompiled = decompiled.substring(0, maxDecompileChars);

        out.println("    {");
        out.println("      \"entry\": " + quote(hex(function.getEntryPoint())) + ",");
        out.println("      \"name\": " + quote(function.getName()) + ",");
        out.println("      \"namespace\": " + quote(function.getParentNamespace().getName(true)) + ",");
        out.println("      \"external\": " + function.isExternal() + ",");
        out.println("      \"thunk\": " + function.isThunk() + ",");
        out.println("      \"signature\": " + quote(function.getSignature().getPrototypeString()) + ",");
        out.println("      \"body_min\": " + quote(hex(function.getBody().getMinAddress())) + ",");
        out.println("      \"body_max\": " + quote(hex(function.getBody().getMaxAddress())) + ",");
        out.println("      \"decompile_ok\": " + (decompiled != null) + ",");
        out.println("      \"decompile_truncated\": " + decompileTruncated + ",");
        out.println("      \"decompiled_c\": " + quote(decompiled) + ",");

        List<CallRecord> callRecords = calls(function);
        out.println("      \"calls\": [");
        for (int index = 0; index < callRecords.size(); ++index) {
            CallRecord record = callRecords.get(index);
            out.print("        {\"site\":" + quote(record.site) +
                ",\"target\":" + quote(record.target) +
                ",\"name\":" + quote(record.name) +
                ",\"kind\":" + quote(record.kind) + "}");
            out.println(index + 1 == callRecords.size() ? "" : ",");
        }
        out.println("      ],");

        out.println("      \"xrefs_to\": [");
        ReferenceIterator references = currentProgram.getReferenceManager().getReferencesTo(
            function.getEntryPoint());
        List<String> xrefs = new ArrayList<>();
        while (references.hasNext()) xrefs.add(hex(references.next().getFromAddress()));
        Collections.sort(xrefs);
        for (int index = 0; index < xrefs.size(); ++index) {
            out.print("        " + quote(xrefs.get(index)));
            out.println(index + 1 == xrefs.size() ? "" : ",");
        }
        out.println("      ],");

        out.println("      \"instructions\": [");
        InstructionIterator instructions = currentProgram.getListing().getInstructions(
            function.getBody(), true);
        int instructionIndex = 0;
        while (instructions.hasNext() && instructionIndex < maxInstructions) {
            Instruction instruction = instructions.next();
            if (instructionIndex != 0) out.println(",");
            byte[] bytes;
            try { bytes = instruction.getBytes(); }
            catch (Exception error) { bytes = new byte[0]; }
            out.print("        {\"address\":" + quote(hex(instruction.getAddress())) +
                ",\"bytes\":" + quote(byteString(bytes)) +
                ",\"mnemonic\":" + quote(instruction.getMnemonicString()) +
                ",\"text\":" + quote(instruction.toString()) + "}");
            ++instructionIndex;
        }
        out.println();
        out.println("      ],");
        out.println("      \"instructions_truncated\": " + instructions.hasNext());
        out.print("    }");
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) throw new IllegalArgumentException(
            "usage: AireceBenchmarkExport.java <out-json> [max-functions] " +
            "[max-instructions-per-function] [max-decompile-chars] [decompile-timeout]");
        File destination = new File(args[0]);
        int maxFunctions = args.length > 1 ? Integer.parseInt(args[1]) : 512;
        int maxInstructions = args.length > 2 ? Integer.parseInt(args[2]) : 2048;
        int maxDecompileChars = args.length > 3 ? Integer.parseInt(args[3]) : 65536;
        int decompileTimeout = args.length > 4 ? Integer.parseInt(args[4]) : 30;
        if (destination.getParentFile() != null) destination.getParentFile().mkdirs();

        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");
        decompiler.openProgram(currentProgram);

        List<Function> functions = new ArrayList<>();
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext() && functions.size() < maxFunctions) {
            Function function = iterator.next();
            if (!function.isExternal()) functions.add(function);
        }
        Collections.sort(functions, Comparator.comparingLong(
            item -> item.getEntryPoint().getOffset()));

        try (PrintWriter out = new PrintWriter(destination, "UTF-8")) {
            out.println("{");
            out.println("  \"schema\": \"airece.ghidra-export.v1\",");
            out.println("  \"program\": {");
            out.println("    \"format\": " + quote(currentProgram.getExecutableFormat()) + ",");
            out.println("    \"language\": " + quote(currentProgram.getLanguageID().toString()) + ",");
            out.println("    \"compiler\": " + quote(currentProgram.getCompilerSpec().getCompilerSpecID().toString()) + ",");
            out.println("    \"image_base\": " + quote(hex(currentProgram.getImageBase())) + ",");
            out.println("    \"min_address\": " + quote(hex(currentProgram.getMinAddress())) + ",");
            out.println("    \"max_address\": " + quote(hex(currentProgram.getMaxAddress())) + ",");
            out.println("    \"executable_sha256\": " + quote(currentProgram.getExecutableSHA256()) +
                ",");
            out.println("    \"function_count\": " + functions.size());
            out.println("  },");
            out.println("  \"functions\": [");
            for (int index = 0; index < functions.size(); ++index) {
                writeFunction(out, functions.get(index), decompiler, decompileTimeout,
                    maxInstructions, maxDecompileChars);
                out.println(index + 1 == functions.size() ? "" : ",");
            }
            out.println("  ],");
            out.println("  \"strings\": [");
            List<Data> strings = new ArrayList<>();
            DataIterator dataIterator = currentProgram.getListing().getDefinedData(true);
            while (dataIterator.hasNext()) {
                Data data = dataIterator.next();
                if (data.getValue() instanceof String) strings.add(data);
            }
            Collections.sort(strings, Comparator.comparingLong(
                item -> item.getAddress().getOffset()));
            for (int index = 0; index < strings.size(); ++index) {
                Data data = strings.get(index);
                out.print("    {\"address\":" + quote(hex(data.getAddress())) +
                    ",\"value\":" + quote(String.valueOf(data.getValue())) + "}");
                out.println(index + 1 == strings.size() ? "" : ",");
            }
            out.println("  ]");
            out.println("}");
        } finally {
            decompiler.dispose();
        }
    }
}
