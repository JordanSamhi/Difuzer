package lu.uni.trux.difuzer;

import java.util.LinkedList;
import java.util.List;

import soot.jimple.infoflow.InfoflowConfiguration;
import soot.jimple.infoflow.InfoflowConfiguration.CallgraphAlgorithm;
import soot.jimple.infoflow.config.IInfoflowConfig;
import soot.options.Options;

public class FlowConfig implements IInfoflowConfig {

	public void setSootOptions(Options options, InfoflowConfiguration config) {
		config.setCallgraphAlgorithm(CallgraphAlgorithm.CHA);
		List<String> includeList = new LinkedList<String>();
		includeList.add("java.lang.*");
		includeList.add("java.util.*");
		includeList.add("java.io.*");
		includeList.add("sun.misc.*");
		includeList.add("java.net.*");
		includeList.add("javax.servlet.*");
		includeList.add("javax.crypto.*");
		includeList.add("android.*");
		includeList.add("org.apache.http.*");
		includeList.add("de.test.*");
		includeList.add("soot.*");
		includeList.add("com.example.*");
		includeList.add("libcore.icu.*");
		includeList.add("securibench.*");
		Options.v().set_no_bodies_for_excluded(true);
		Options.v().set_allow_phantom_refs(true);
		Options.v().set_src_prec(Options.src_prec_apk);
		options.set_include(includeList);
		options.set_output_format(Options.output_format_none);
		Options.v().setPhaseOption("jb", "use-original-names:true");
		Options.v().set_ignore_classpath_errors(true);
	}
}
