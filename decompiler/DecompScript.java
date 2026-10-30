// DecompScript.java
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.File;
import java.io.FileWriter;

public class DecompScript extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("-> [Java] Script di decompilazione avviato...");

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);

        // Genera il file .c di output nella cartella di lavoro corrente
        String outputFileName = "decompiled_files/" + currentProgram.getName() + "_decompiled.c";
        File outputFile = new File(System.getProperty("user.dir"), outputFileName);

        // NUOVO: mappa indirizzo -> nome funzione, risolta da Ghidra via DWARF.
        // Serve a rietichettare i grafi di angr_cfglib.py (che non ha accesso
        // ai simboli DWARF e chiama tutto "sub_<indirizzo>").
        String symbolsFileName = "decompiled_files/" + currentProgram.getName() + "_symbols.json";
        File symbolsFile = new File(System.getProperty("user.dir"), symbolsFileName);

        try (FileWriter writer = new FileWriter(outputFile);
             FileWriter symWriter = new FileWriter(symbolsFile)) {

            symWriter.write("{\n");
            boolean first = true;

            while (functions.hasNext() && !monitor.isCancelled()) {
                Function func = functions.next();
                DecompileResults results = decomp.decompileFunction(func, 0, new ConsoleTaskMonitor());

                if (results != null && results.decompileCompleted()) {
                    // Scrive direttamente il codice C decompilato
                    writer.write(results.getDecompiledFunction().getC() + "\n\n");
                }

                // Indirizzo in esadecimale puro (es. "004012e0"), stessa
                // convenzione di indirizzamento assoluto usata da angr
                // quando carica lo stesso binario (nessuna ASLR in
                // analisi statica, image base identico).
                String addrHex = func.getEntryPoint().toString(false);
                String name = func.getName().replace("\"", "\\\"");

                if (!first) {
                    symWriter.write(",\n");
                }
                first = false;
                symWriter.write("  \"" + addrHex + "\": \"" + name + "\"");
            }

            symWriter.write("\n}\n");
        }

        println("-> [Java] Decompilazione completata! File salvato in: " + outputFile.getAbsolutePath());
        println("-> [Java] Simboli esportati in: " + symbolsFile.getAbsolutePath());
    }
}