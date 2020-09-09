package lu.uni.trux.difuzer;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import lu.uni.trux.difuzer.utils.Constants;
import soot.Scene;
import soot.jimple.infoflow.IInfoflow;
import soot.jimple.infoflow.Infoflow;
import soot.jimple.infoflow.results.InfoflowResults;
import soot.jimple.infoflow.taintWrappers.EasyTaintWrapper;

public class FlowAnalysis {
	
	private Logger logger = LoggerFactory.getLogger(this.getClass());
	
	private List<String> sources;
	private List<String> sinks;
	
	public FlowAnalysis() {
		this.sources = new ArrayList<String>();
		this.sinks = new ArrayList<String>();
	}
	
	public void run(String pathToClassFiles) {
		try {
			this.populateSourcesAndSinks();
			String appPath = null;
			String libPath = null;
			IInfoflow infoflow = null;
			List<String> epoints = null;

			appPath = pathToClassFiles;
			libPath = Scene.v().getSootClassPath();
			infoflow = initInfoflow();
			epoints = new ArrayList<String>();
			//TODO change, does not have to be hard coded
//			epoints.add("<sun.reflect.annotation.AnnotationInvocationHandler: void readObject(java.io.ObjectInputStream)>");
			infoflow.computeInfoflow(appPath, libPath, epoints, sources, sinks);
			checkInfoflow(infoflow, 1);
		} catch (Throwable t) {
			t.printStackTrace();
			System.out.println("exception: " + t);
		}
	}
	
	private void populateSourcesAndSinks() {
		InputStream fis = null;
		BufferedReader br = null;
		String line = null;
		try {
//			fis = this.getClass().getResourceAsStream(Constants.SOURCES_AND_SINKS_FILE);
			br = new BufferedReader(new InputStreamReader(fis));
			while ((line = br.readLine()) != null) {
				String[] split = line.split(" -> ");
				if(split.length == 2) {
					String method = split[0];
					String type = split[1];
					if(type.equals(Constants.SOURCE)) {
						sources.add(method);
					}else if(type.equals(Constants.SINK)) {
						sinks.add(method);
					}
				}
			}
		} catch (IOException e) {
			logger.error(e.getMessage());
		}
		try {
			br.close();
			fis.close();
		} catch (IOException e) {
			logger.error(e.getMessage());
		}
	}

	protected void checkInfoflow(IInfoflow infoflow, int resultCount) {
	if (infoflow.isResultAvailable()) {
		InfoflowResults results = infoflow.getResults();
		System.out.println(results);
		System.out.println("Taint analysis results:");
		results.printResults();
//		for (ResultSinkInfo sink : results.getResults().keySet()) {
//			System.out.println("Found a flow to sink " + sink + ", from the following sources:");
//			for (ResultSourceInfo source : results.getResults().get(sink)) {
//				System.out.println("\t- " + source + ")");
//				if (source.getPath() != null)
//					System.out.println("\t\ton Path " + Arrays.toString(source.getPath()));
//			}
//		}
	} else {
		System.err.println("No result available.");
	}
}
	
	protected IInfoflow initInfoflow() {
		return initInfoflow(false);
	}

	protected IInfoflow initInfoflow(boolean useTaintWrapper) {
		Infoflow result = new Infoflow("", false, null);
		result.setSootConfig( new FlowConfig());
		if (useTaintWrapper) {
			EasyTaintWrapper easyWrapper;
			easyWrapper = new EasyTaintWrapper(null, null);
			result.setTaintWrapper(easyWrapper);
		}
		return result;
	}
}
