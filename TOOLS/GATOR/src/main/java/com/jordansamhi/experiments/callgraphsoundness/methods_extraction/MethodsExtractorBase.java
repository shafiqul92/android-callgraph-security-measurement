package com.jordansamhi.experiments.callgraphsoundness.methods_extraction;

import com.jordansamhi.androspecter.printers.Writer;
import com.jordansamhi.experiments.callgraphsoundness.utils.DataCollector;
import soot.Scene;
import soot.jimple.toolkits.callgraph.CallGraph;

import java.io.File;
import java.util.List;
import java.util.concurrent.*;

public abstract class MethodsExtractorBase {

    public void run(String apkPath) {
        List<String> algos = this.getAlgos();
        DataCollector dc = new DataCollector();

        try {
            Writer.v().pinfo("Initializing Environment");
            Writer.v().pinfo(apkPath);
            this.initEnv(apkPath);
            //Writer.v().pinfo("Initialized Environment");
            for (String algo : algos) {
                final CallGraph[] cg = {null};
                ExecutorService executor = Executors.newSingleThreadExecutor();
                try {
                    Future<String> future = executor.submit(() -> {
                        Writer.v().pinfo(String.format("Processing %s call graph algorithm", algo));
                        buildCallGraph(algo, apkPath);
                        cg[0] = Scene.v().getCallGraph();
                        Writer.v().psuccess("Call graph built");
                        return "Task completed successfully";
                    });
                    try {
                        String result = future.get(60, TimeUnit.MINUTES);
                        dc.collect(result, apkPath, algo, cg[0]);
                    } catch (TimeoutException e) {
                        Writer.v().perror("Timeout reached");
                    } catch (ExecutionException e) {
                        Writer.v().perror(String.format("An exception occurred within the task: %s", e.getMessage()));
                    }
                } finally {
                    executor.shutdown();
                }
            }

            // APK file kept after analysis
        } catch (Exception e) {
            Writer.v().perror(String.format("An exception occurred: %s", e.getMessage()));
        }
    }

    protected abstract void initEnv(String apkPath);

    protected abstract void buildCallGraph(String algo, String appName);

    protected abstract List<String> getAlgos();
}
