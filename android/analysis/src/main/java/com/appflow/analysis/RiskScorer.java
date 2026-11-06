package com.appflow.analysis;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Explainable risk score 0-100: every alert adds visible points.
 *
 *   points = severity points (high 30, medium 15, low 5) x evidence weight
 *   evidence weight: observed 1.0, inferred 0.6, potential_risk 0.4, not_observable 0
 *   each rule adds at most 40 points in total; the score is capped at 100.
 *   level: 0-39 low, 40-69 medium, 70-100 high (same thresholds as the backend).
 *
 * Each alert's points are also stored in alert.riskPoints so the dashboard/PDF can show them.
 */
public final class RiskScorer {

    public static final int MAX_PER_RULE = 40;

    /** The result: number, level and a human-readable breakdown. */
    public static final class Score {
        public final int score;
        public final String level;
        public final List<String> breakdown;

        Score(int score, String level, List<String> breakdown) {
            this.score = score;
            this.level = level;
            this.breakdown = Collections.unmodifiableList(breakdown);
        }
    }

    public static int severityPoints(String severity) {
        switch (severity) {
            case "high": return 30;
            case "medium": return 15;
            case "low": return 5;
            default: return 0;
        }
    }

    public static double evidenceWeight(String evidenceType) {
        switch (evidenceType) {
            case "observed": return 1.0;
            case "inferred": return 0.6;
            case "potential_risk": return 0.4;
            default: return 0.0;   // not_observable adds nothing
        }
    }

    public static String level(int score) {
        if (score >= 70) return "high";
        if (score >= 40) return "medium";
        return "low";
    }

    /** Score ALL alerts of the session so far (in the order they were found). */
    public Score score(List<DetectionEngine.Alert> alerts) {
        Map<String, Integer> perRule = new HashMap<>();
        List<String> lines = new ArrayList<>();
        int total = 0;
        for (DetectionEngine.Alert a : alerts) {
            int raw = (int) Math.round(severityPoints(a.severity) * evidenceWeight(a.evidenceType));
            int used = perRule.getOrDefault(a.ruleId, 0);
            int pts = Math.max(0, Math.min(raw, MAX_PER_RULE - used));
            perRule.put(a.ruleId, used + pts);
            a.riskPoints = pts;
            a.evidence.put("risk_points", pts);
            total += pts;
            lines.add("+" + pts + " " + a.ruleId + " (" + a.severity + ", " + a.evidenceType + ")"
                    + (a.relatedIp != null ? " " + a.relatedIp : ""));
        }
        int score = Math.min(100, total);
        return new Score(score, level(score), lines);
    }
}
