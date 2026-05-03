package com.jordansamhi.experiments.callgraphsoundness.methods_extraction;

import com.jordansamhi.androspecter.commonlineoptions.CommandLineOption;
import com.jordansamhi.androspecter.commonlineoptions.CommandLineOptions;

/**
 * The `MethodsExtractorMain` class provides an entry point for the APK methods extraction process.
 * The process involves the use of various tools such as Flowdroid, ICCTA, RAICC, DroidRA, MaMaDroid, and SootFX.
 * <p>
 * The main method of this class initiates the process by parsing the command line options to determine
 * the specific tool to be used for the extraction. Depending on the tool specified, an appropriate
 * instance of `MethodsExtractorBase` is created and its `run` method is invoked.
 * <p>
 * If the specified tool is not recognized, an `IllegalArgumentException` is thrown.
 *
 * @author Jordan Samhi
 * @see MethodsExtractorBase
 * @see MethodsExtractorFlowdroid
 * @see MethodsExtractorICCTA
 * @see MethodsExtractorRAICC
 * @see MethodsExtractorDroidRA
 * @see MethodsExtractorMaMaDroid
 * @see MethodsExtractorSootFX
 */
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
            case "natidroid":
                meb = new MethodsExtractorNatiDroid();
                break;
            
            default:
                throw new IllegalArgumentException("Invalid tool: " + tool);
        }
        meb.run(apkPath);
    }
}