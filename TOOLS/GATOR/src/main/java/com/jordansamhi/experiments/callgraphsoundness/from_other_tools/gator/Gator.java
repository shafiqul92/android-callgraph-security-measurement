package com.jordansamhi.experiments.callgraphsoundness.from_other_tools.gator;

import soot.PackManager;
import soot.Scene;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.options.Options;

import java.util.ArrayList;
import java.util.List;

import com.jordansamhi.androspecter.printers.Writer;

public class Gator {

    public static void main(String[] args) {
        String platforms = "";
        String apkt_path = "";
        Gator.setupAndInvokeSoot(platforms, apkt_path);
        Gator.buildCallGraph();
        CallGraph cg = Scene.v().getCallGraph();
        System.out.println("CallGraph size: " + cg.size());
    }

    public static void setupAndInvokeSoot(String android_jar, String apk_path) {
        //Writer.v().pinfo("setting up 1");
        Options.v().set_whole_program(true);
        //Writer.v().pinfo("setting up 2");
        Options.v().setPhaseOption("cg", "all-reachable:true");
        //Writer.v().pinfo("setting up 3");
        Options.v().setPhaseOption("cg.cha", "enabled:true");
        //Writer.v().pinfo("setting up 4");
        Options.v().setPhaseOption("wjtp.gui", "enabled:true");
        Options.v().set_output_format(Options.output_format_n);
        Options.v().set_keep_line_number(true);
        Options.v().set_process_multiple_dex(true);
        Options.v().set_allow_phantom_refs(true);
        List<String> apks = new ArrayList<>();
        //Writer.v().pinfo("setting up 5");
        apks.add(apk_path);
        //Writer.v().pinfo("setting up 6");
        Options.v().set_src_prec(Options.src_prec_apk);
        Options.v().set_process_dir(apks);
        //Writer.v().pinfo("setting up 7");
        Writer.v().pinfo(android_jar);
        Options.v().set_android_jars(android_jar);
        //Writer.v().pinfo("setting up 8");  // Set Android JARs here
        Scene.v().loadNecessaryClasses();
        //Writer.v().pinfo("setting up 9");
    }

    public static void buildCallGraph() {
        //Writer.v().pinfo("setting up 10");
        PackManager.v().runPacks();
        //Writer.v().pinfo("setting up 11");
    }
}
