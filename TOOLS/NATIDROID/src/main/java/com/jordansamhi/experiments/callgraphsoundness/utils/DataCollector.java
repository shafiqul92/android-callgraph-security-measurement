package com.jordansamhi.experiments.callgraphsoundness.utils;

import com.jordansamhi.androspecter.SootUtils;
import com.jordansamhi.androspecter.printers.Writer;
import soot.SootMethod;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

public class DataCollector {

    public DataCollector() {}

    public void collect(String result, String appName, String algo, CallGraph cg) {
        if (result.equals("Task completed successfully")) {
            System.out.println("HERE");

            SootUtils su = new SootUtils();
            Set<SootMethod> allMethods = su.getAllMethods();

            Map<SootMethod, List<SootMethod>> adjacencyList = new HashMap<>();
            for (Edge e : cg) {
                if (e != null) {
                    SootMethod srcMethod = e.src();
                    SootMethod tgtMethod = e.tgt();
                    adjacencyList.putIfAbsent(srcMethod, new ArrayList<>());
                    adjacencyList.get(srcMethod).add(tgtMethod);
                }
            }

            String adjacencyListStr = adjacencyList.entrySet().stream()
                    .filter(entry -> entry.getKey() != null && entry.getValue() != null)
                    .flatMap(entry -> entry.getValue().stream()
                            .filter(Objects::nonNull)
                            .map(target -> entry.getKey().toString() + " -> " + target.toString())
                    )
                    .collect(Collectors.joining("\n"));
            String allMethodsStr = allMethods.stream()
                    .map(SootMethod::toString)
                    .collect(Collectors.joining("|"));

            String fileContent = String.format("App: %s\nAlgorithm: %s\nAll Methods:\n%s\n\nCall Graph:\n%s",
                    appName, algo, allMethodsStr, adjacencyListStr);

            saveDataToFile(appName, algo, fileContent);
        }
    }

    private void saveDataToFile(String appName, String algo, String content) {
        String fileName = String.format("%s-%s-callgraph.txt", appName, algo);

        try (FileOutputStream fos = new FileOutputStream(new File(fileName))) {
            fos.write(content.getBytes());
            Writer.v().psuccess("Data successfully saved to " + fileName);
        } catch (IOException e) {
            Writer.v().perror("Failed to save data: " + e.getMessage());
        }
    }
}
