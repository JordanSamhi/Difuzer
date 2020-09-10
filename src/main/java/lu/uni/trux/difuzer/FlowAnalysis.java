package lu.uni.trux.difuzer;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmlpull.v1.XmlPullParserException;

import lu.uni.trux.difuzer.utils.CommandLineOptions;
import redis.clients.jedis.Jedis;
import soot.jimple.infoflow.InfoflowConfiguration.CallgraphAlgorithm;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.results.InfoflowResults;
import soot.jimple.infoflow.results.ResultSinkInfo;

public class FlowAnalysis {

	private Logger logger = LoggerFactory.getLogger(this.getClass());

	CommandLineOptions options;
	String apk;

	public FlowAnalysis(CommandLineOptions o, String a) {
		this.options = o;
		this.apk = a;
	}

	public void run() {
		// Flowdroid config
		InfoflowAndroidConfiguration ifac = new InfoflowAndroidConfiguration();
		ifac.setIgnoreFlowsInSystemPackages(false);
		ifac.getAnalysisFileConfig().setAndroidPlatformDir(options.getPlatforms());
		ifac.getAnalysisFileConfig().setTargetAPKFile(this.apk);
		ifac.setCallgraphAlgorithm(CallgraphAlgorithm.CHA);
		SetupApplication sa = new SetupApplication(ifac);
		sa.constructCallgraph();

		sa.constructCallgraph();

		// Taint wrapper
		//		if(options.hasEasyTaintWrapperFile()) {
		//			final ITaintPropagationWrapper taintWrapper;
		//			EasyTaintWrapper easyTaintWrapper = null;
		//			File twSourceFile = new File(options.getEasyTaintWrapperFile());
		//			if (twSourceFile.exists())
		//				easyTaintWrapper = new EasyTaintWrapper(twSourceFile);
		//			else {
		//				System.err.println("Taint wrapper definition file not found at "
		//						+ twSourceFile.getAbsolutePath());
		//			}
		//			easyTaintWrapper.setAggressiveMode(true);
		//			taintWrapper = easyTaintWrapper;
		//			sa.setTaintWrapper(taintWrapper);
		//		}

		InfoflowResults res = null;
		try {
			res = sa.runInfoflow(options.getSourcesSinksFile());
		} catch (IOException e) {
			logger.error(e.getMessage());
		} catch (XmlPullParserException e) {
			logger.error(e.getMessage());
		}
		
		// Process results
		if(res != null) {
			if(res.getResults() != null && !res.getResults().isEmpty()) {
				for (ResultSinkInfo sink : res.getResults().keySet()) {
					logger.info(String.format("Sensitive information found in condition : %s", sink));
					//				for (ResultSourceInfo source : res.getResults().get(sink)) {
					//					System.out.println("\t- " + source + ")");
					//					if (source.getPath() != null)
					//						System.out.println("\t\ton Path " + Arrays.toString(source.getPath()));
					//				}
				}
			}
		}
	}
}
