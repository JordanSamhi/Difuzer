package lu.uni.trux.difuzer;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import lu.uni.trux.difuzer.instrumentation.IfClassGenerator;
import lu.uni.trux.difuzer.utils.CommandLineOptions;
import soot.G;
import soot.PackManager;
import soot.Scene;
import soot.SceneTransformer;
import soot.Transform;
import soot.options.Options;

public class PreAnalysis {
	
	private CommandLineOptions options;

	private Logger logger = LoggerFactory.getLogger(Main.class);

	public PreAnalysis(String[] args) {
		this.options = new CommandLineOptions(args);
	}
	
	public void run() {
		this.logger.debug("Initializing Soot for Pre-Analysis");
		initializeSoot();
		this.logger.debug("Initializing new classes for Pre-Analysis");
		initializeNewClasses();
		PackManager.v().getPack("wjtp").add(new Transform("wjtp.myTransform", new SceneTransformer() {
			protected void internalTransform(String phaseName, @SuppressWarnings("rawtypes") Map options) {

			}
		}));
		PackManager.v().runPacks();
	}
	
	private void initializeNewClasses() {
		IfClassGenerator.v().generateClass();
	}

	private void initializeSoot() {
		G.reset();
		Options.v().set_src_prec(Options.src_prec_apk);
		Options.v().set_output_format(Options.output_format_dex);
		Options.v().set_allow_phantom_refs(true);
		Options.v().set_whole_program(true);
		Options.v().set_android_jars(this.options.getPlatforms());
		List<String> apps = new ArrayList<String>();
		apps.add(this.options.getApk());
		Options.v().set_process_dir(apps);
		Options.v().set_output_dir(this.options.getOutput());
		Options.v().set_force_overwrite(true);
		Scene.v().loadNecessaryClasses();
	}
}
