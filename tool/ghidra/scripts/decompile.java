import java.io.FileWriter;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
public class decompile extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        FileWriter out = new FileWriter(args[0]);
        boolean includeAddresses = args.length > 2 && Boolean.parseBoolean(args[2]);
        Address a = currentProgram.getAddressFactory().getAddress(args[1]);
        Function f = currentProgram.getFunctionManager().getFunctionContaining(a);
        if (f == null) { out.write("{\"error\":\"function not found\"}"); out.close(); return; }
        DecompInterface d = new DecompInterface(); d.openProgram(currentProgram);
        DecompileResults r = d.decompileFunction(f, 60, monitor);
        out.write("{\"name\":" + q(f.getName()));
        out.write(",\"address\":" + q(f.getEntryPoint().toString()));
        out.write(",\"code\":" + q(r.decompileCompleted() ? r.getDecompiledFunction().getC() : ""));
        out.write("}"); d.dispose(); out.close();
    }
    String q(String s) {
        if (s == null) return "null";
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + "\"";
    }
}

