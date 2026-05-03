package com.jordansamhi.experiments.callgraphsoundness.methods_extraction;

import com.jordansamhi.androspecter.commonlineoptions.CommandLineOption;
import com.jordansamhi.androspecter.commonlineoptions.CommandLineOptions;

public class MethodsExtractorMain {
    public static void main(String[] args) {
        CommandLineOptions options = CommandLineOptions.v();
        options.setAppName("AndroLibZoo FlowDroid Experiment");
        options.addOption(new CommandLineOption("platforms", "p", "Platform file", true, true));
        options.addOption(new CommandLineOption("tool", "t", "The tool to use", true, true));
        options.addOption(new CommandLineOption("apk", "a", "The APK to process", true, true));
        options.addOption(new CommandLineOption("android-jars", "j", "Android JAR file path", true, true));  // Added android-jars
        options.parseArgs(args);
        String tool = CommandLineOptions.v().getOptionValue("tool");
        String apkPath = CommandLineOptions.v().getOptionValue("apk");

        MethodsExtractorBase meb;

        switch (tool) {
            case "gator":
                meb = new MethodsExtractorGator(apkPath);
                break;

            default:
                throw new IllegalArgumentException("Invalid tool: " + tool);
        }
        meb.run(apkPath);
    }
}
