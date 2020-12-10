package lu.uni.trux.difuzer;

import java.util.ArrayList;
import java.util.List;

import lu.uni.trux.difuzer.triggers.TriggerIfCall;
import redis.clients.jedis.Jedis;
import soot.SootMethod;

/*-
 * #%L
 * Difuzer
 * 
 * %%
 * Copyright (C) 2021 Jordan Samhi
 * University of Luxembourg - Interdisciplinary Centre for
 * Security Reliability and Trust (SnT) - TruX - All rights reserved
 *
 * %%
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Lesser Public License for more details.
 * 
 * You should have received a copy of the GNU General Lesser Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/lgpl-2.1.html>.
 * #L%
 */

public class ResultsAccumulator {

	private static ResultsAccumulator instance;

	private int instrumentedIfCount;
	private int flowsFoundCount;
	private int analysisElapsedTime;
	private int taintAnalysisElapsedTime;
	private int instrumentationElapsedTime;
	private int triggersAfterAnomalyDetection;
	private int triggersBeforeAnomalyDetection;
	List<TriggerIfCall> triggersFound;

	private String appName;

	private ResultsAccumulator () {
		this.setInstrumentedIfCount(0);
		this.setFlowsFoundCount(0);
		this.setTaintAnalysisElapsedTime(0);
		this.setInstrumentationElapsedTime(0);
		this.setAnalysisElapsedTime(0);
		this.setTriggersBeforeAnomalyDetection(0);
		this.setTriggersAfterAnomalyDetection(0);
		this.setAppName("");
		this.triggersFound = new ArrayList<TriggerIfCall>();
	}

	public static ResultsAccumulator v() {
		if(instance == null) {
			instance = new ResultsAccumulator();
		}
		return instance;
	}

	public void incrementIfCount() {
		this.setInstrumentedIfCount(this.getInstrumentedIfCount() + 1);
	}

	public void incrementFlowsCount() {
		this.setFlowsFoundCount(this.getFlowsFoundCount() + 1);
	}

	public int getInstrumentedIfCount() {
		return instrumentedIfCount;
	}

	public void setInstrumentedIfCount(int instrumentedIfCount) {
		this.instrumentedIfCount = instrumentedIfCount;
	}

	public int getFlowsFoundCount() {
		return flowsFoundCount;
	}

	public void setFlowsFoundCount(int flowFoundCount) {
		this.flowsFoundCount = flowFoundCount;
	}

	public int getAnalysisElapsedTime() {
		return analysisElapsedTime;
	}

	public void setAnalysisElapsedTime(int t) {
		this.analysisElapsedTime = t;
	}

	public String getAppName() {
		return appName;
	}

	public void setAppName(String appName) {
		this.appName = appName;
	}

	public List<TriggerIfCall> getTriggersFound() {
		return triggersFound;
	}

	public void setTriggersFound(List<TriggerIfCall> triggersFound) {
		this.triggersFound = triggersFound;
		this.setTriggersAfterAnomalyDetection(this.triggersFound.size());
	}

	public void printVectorResults() {
		System.out.println(this.generateVector());
	}

	public void printTriggersResults() {
		if(this.triggersFound.isEmpty()) {
			System.out.println("No potential logic bomb found.");
		}else {
			for(TriggerIfCall t: this.triggersFound) {
				System.out.println("\n- Potential logic bomb found in: " + t.getMethod());
				System.out.println("  - Condition: " + t.getCondition());
				System.out.println("  - Test performed on following potential values: ");
				for(SootMethod source: t.getSources()) {
					System.out.println("    - " + source);
				}
			}
		}
	}

	public void sendResultsToRedisServer(String server, String auth, String redisList) {
		Jedis jedis = new Jedis(server);
		if(auth != null) {
			jedis.auth(auth);
		}
		jedis.select(0);
		jedis.lpush(redisList, this.generateVector());
		jedis.close();
	}

	private String generateVector() {
		return String.format("%s;%s;%s;%s;%s;%s;%s;%s", this.getAppName(), this.getInstrumentedIfCount(),
				this.getFlowsFoundCount(), this.getAnalysisElapsedTime(), this.getTriggersBeforeAnomalyDetection(),
				this.getTriggersAfterAnomalyDetection(), this.getTaintAnalysisElapsedTime(), this.getInstrumentationElapsedTime());
	}

	public int getTriggersAfterAnomalyDetection() {
		return triggersAfterAnomalyDetection;
	}

	public void setTriggersAfterAnomalyDetection(int triggersAfterAnomalyDetection) {
		this.triggersAfterAnomalyDetection = triggersAfterAnomalyDetection;
	}

	public int getTriggersBeforeAnomalyDetection() {
		return triggersBeforeAnomalyDetection;
	}

	public void setTriggersBeforeAnomalyDetection(int triggersBeforeAnomalyDetection) {
		this.triggersBeforeAnomalyDetection = triggersBeforeAnomalyDetection;
	}

	public int getTaintAnalysisElapsedTime() {
		return taintAnalysisElapsedTime;
	}

	public void setTaintAnalysisElapsedTime(int taintAnalysisElapsedTime) {
		this.taintAnalysisElapsedTime = taintAnalysisElapsedTime;
	}

	public int getInstrumentationElapsedTime() {
		return instrumentationElapsedTime;
	}

	public void setInstrumentationElapsedTime(int instrumentationElapsedTime) {
		this.instrumentationElapsedTime = instrumentationElapsedTime;
	}
}