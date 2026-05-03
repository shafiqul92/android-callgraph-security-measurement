package com.jordansamhi.experiments.callgraphsoundness.methods_extraction;

import com.jordansamhi.androspecter.commonlineoptions.CommandLineOptions;
import com.jordansamhi.experiments.callgraphsoundness.from_other_tools.gator.Gator;

import java.util.Collections;
import java.util.List;

public class MethodsExtractorGator extends MethodsExtractorBase {

    private String apkPath;

    // Constructor to pass apkPath directly
    public MethodsExtractorGator(String apkPath) {
        this.apkPath = apkPath;
    }

    @Override
    protected void initEnv(String apkPath) {
        String platformsPath = CommandLineOptions.v().getOptionValue("platforms");
        Gator.setupAndInvokeSoot(platformsPath, this.apkPath);
    }

    @Override
    protected void buildCallGraph(String algo, String appName) {
        Gator.buildCallGraph();
    }

    @Override
    protected List<String> getAlgos() {
        return Collections.singletonList("CHA");
    }
}
