package lu.uni.trux.difuzer.managers;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashSet;
import java.util.Set;

import lu.uni.trux.difuzer.utils.Constants;
import lu.uni.trux.difuzer.utils.Utils;
import soot.SootMethod;
import soot.jimple.infoflow.android.data.AndroidMethod;

public class SourcesSinksManager {
	
	private static SourcesSinksManager instance;
	private Set<AndroidMethod> sources;
	private Set<AndroidMethod> sinks;
	
	private SourcesSinksManager () {
		this.sources = new HashSet<AndroidMethod>();
		this.sinks = new HashSet<AndroidMethod>();
		this.loadSourcesSinksFromFile();
	}

	public static SourcesSinksManager v() {
		if(instance == null) {
			instance = new SourcesSinksManager();
		}
		return instance;
	}
	
	private void loadSourcesSinksFromFile() {
		InputStream fis = null;
		BufferedReader br = null;
		String line = null;
		try {
			fis = this.getClass().getResourceAsStream(Constants.SOURCES_AND_SINKS_FILE);
			br = new BufferedReader(new InputStreamReader(fis));
			while ((line = br.readLine()) != null) {
				String[] split = line.split(" -> ");
				if(split.length == 2) {
					String method = split[0];
					String type = split[1];
					if(type.equals(Constants.SOURCE)) {
						this.sources.add(new AndroidMethod(Utils.getMethodNameFromSignature(method),
								Utils.getParametersNamesFromSignature(method),
								Utils.getReturnNameFromSignature(method),
								Utils.getClassNameFromSignature(method)));
					}else if(type.equals(Constants.SINK)) {
						this.sinks.add(new AndroidMethod(Utils.getMethodNameFromSignature(method),
						Utils.getParametersNamesFromSignature(method),
						Utils.getReturnNameFromSignature(method),
						Utils.getClassNameFromSignature(method)));
					}
				}
			}
		} catch (IOException e) {
			System.err.println(e.getMessage());
		}
		try {
			br.close();
			fis.close();
		} catch (IOException e) {
			System.err.println(e.getMessage());
		}
	}

	public Set<AndroidMethod> getSources() {
		return this.sources;
	}

	public Set<AndroidMethod> getSinks() {
		return this.sinks;
	}

	public void addSink(SootMethod sm) {
		this.sinks.add(new AndroidMethod(sm));
	}
}