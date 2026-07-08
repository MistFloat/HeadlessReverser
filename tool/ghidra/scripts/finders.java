import java.io.FileWriter; import java.util.HashSet;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data; import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference; import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol; import ghidra.program.model.symbol.SymbolIterator;
public class finders extends GhidraScript {
    FileWriter out;
    public void run() throws Exception {
        String[] a = getScriptArgs(); out = new FileWriter(a[0]);
        if (a[1].equals("calling")) funcsCalling(a[2],Integer.parseInt(a[3]));
        if (a[1].equals("string_refs")) funcsRefStr(a[2],Integer.parseInt(a[3]));
        out.close();
    }
    void funcsCalling(String name, int limit) throws Exception {
        HashSet<String> seen = new HashSet<>(); int count = 0;
        out.write("{\"query\":"+q(name)+",\"functions\":[");
        SymbolIterator symbols = currentProgram.getSymbolTable().getAllSymbols(true);
        while (symbols.hasNext() && count < limit) {
            Symbol s = symbols.next();
            if (!s.getName().toLowerCase().contains(name.toLowerCase())) continue;
            ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(s.getAddress());
            while (refs.hasNext() && count < limit) {
                Reference r = refs.next();
                Function f = currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
                if (f == null) continue;
                String key = f.getEntryPoint().toString();
                if (seen.contains(key)) continue; seen.add(key);
                if (count>0) out.write(",");
                out.write("{\"address\":"+q(f.getEntryPoint().toString())+",\"name\":"+q(f.getName()));
                out.write(",\"ref\":"+q(r.getFromAddress().toString())+",\"target\":"+q(s.getName())+"}"); count++;
            }
        }
        out.write("]}");
    }
    void funcsRefStr(String query, int limit) throws Exception {
        HashSet<String> seen = new HashSet<>(); int count = 0; String needle = query.toLowerCase();
        out.write("{\"query\":"+q(query)+",\"functions\":[");
        for (Data data : currentProgram.getListing().getDefinedData(true)) {
            if (count>=limit) break;
            if (!StringDataInstance.isString(data)) continue;
            String value = StringDataInstance.getStringDataInstance(data).getStringValue();
            if (value==null||!value.toLowerCase().contains(needle)) continue;
            ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(data.getAddress());
            while (refs.hasNext() && count<limit) {
                Reference r = refs.next();
                Function f = currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
                if (f==null) continue;
                String key = f.getEntryPoint().toString()+":"+data.getAddress().toString();
                if (seen.contains(key)) continue; seen.add(key);
                if (count>0) out.write(",");
                out.write("{\"address\":"+q(f.getEntryPoint().toString())+",\"name\":"+q(f.getName()));
                out.write(",\"string\":"+q(value)+"}"); count++;
            }
        }
        out.write("]}");
    }
    String q(String s) { return s==null?"null":"\""+s.replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n").replace("\r","\\r")+"\""; }
}
