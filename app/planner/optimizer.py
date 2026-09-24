from typing import List
from app.models.finding import VulnerabilityFinding, RemediationPlan

class RemediationOptimizer:
    """
    Capacity-Constrained Remediation Optimizer for HTH-CS-03.
    Uses an exact 0/1 Knapsack Dynamic Programming algorithm to select the subset 
    of vulnerabilities that yields maximum total Business Risk reduction within 
    the available engineering capacity (hours).
    """

    @classmethod
    def optimize_plan(cls, findings: List[VulnerabilityFinding], available_capacity: float) -> RemediationPlan:
        """
        Solves the 0/1 Knapsack problem for vulnerability remediation planning.
        """
        if not findings or available_capacity <= 0:
            total_initial_risk = round(sum(f.business_risk or 0.0 for f in findings), 2)
            deferred = [f.model_copy(update={"remediation_status": "DEFERRED"}) for f in findings]
            return RemediationPlan(
                available_capacity=round(available_capacity, 2),
                total_effort_used=0.0,
                remaining_capacity=max(0.0, round(available_capacity, 2)),
                total_risk_reduced=0.0,
                total_initial_risk=total_initial_risk,
                risk_reduction_percentage=0.0,
                selected_count=0,
                deferred_count=len(deferred),
                selected_vulnerabilities=[],
                deferred_vulnerabilities=deferred,
                optimization_rationale=f"Available capacity is {available_capacity}h. All vulnerabilities deferred to future sprints."
            )

        # Scale float values to integer precision for exact DP Knapsack (scale x10)
        SCALE = 10
        capacity_int = int(round(available_capacity * SCALE))
        n = len(findings)

        weights = [int(round(f.remediation_effort * SCALE)) for f in findings]
        values = [f.business_risk or 0.0 for f in findings]

        # DP Table: dp[i][w] = max value attainable with first i items and capacity w
        dp = [[0.0] * (capacity_int + 1) for _ in range(n + 1)]

        for i in range(1, n + 1):
            w_i = weights[i - 1]
            v_i = values[i - 1]
            for w in range(capacity_int + 1):
                if w_i <= w:
                    dp[i][w] = max(dp[i - 1][w], dp[i - 1][w - w_i] + v_i)
                else:
                    dp[i][w] = dp[i - 1][w]

        # Backtrack to find selected items
        selected_indices = set()
        w = capacity_int
        for i in range(n, 0, -1):
            if dp[i][w] != dp[i - 1][w]:
                selected_indices.add(i - 1)
                w -= weights[i - 1]

        selected = []
        deferred = []
        for idx, f in enumerate(findings):
            if idx in selected_indices:
                selected.append(f.model_copy(update={"remediation_status": "SELECTED"}))
            else:
                deferred.append(f.model_copy(update={"remediation_status": "DEFERRED"}))

        # Calculate metrics
        total_effort_used = round(sum(f.remediation_effort for f in selected), 2)
        remaining_capacity = round(max(0.0, available_capacity - total_effort_used), 2)
        total_risk_reduced = round(sum(f.business_risk or 0.0 for f in selected), 2)
        total_initial_risk = round(sum(f.business_risk or 0.0 for f in findings), 2)

        risk_reduction_percentage = (
            round((total_risk_reduced / total_initial_risk) * 100.0, 1)
            if total_initial_risk > 0 else 0.0
        )

        # Generate Human-Readable Rationale
        selected_ids = ", ".join([f.finding_id for f in selected])
        deferred_ids = ", ".join([f.finding_id for f in deferred])

        deferred_higher_brs = []
        min_selected_brs = min([f.business_risk or 0.0 for f in selected]) if selected else float('inf')
        for d in deferred:
            if (d.business_risk or 0.0) > min_selected_brs:
                deferred_higher_brs.append(f"{d.finding_id} (BRS {d.business_risk}, Effort {d.remediation_effort}h)")

        rationale = f"Evaluated all {n} findings under {available_capacity}h capacity limit. Selected {len(selected)} vulnerabilities [{selected_ids}] using {total_effort_used}h effort, addressing {total_risk_reduced} BRS ({risk_reduction_percentage}% of total risk)."
        if deferred_higher_brs:
            rationale += f" Note: Higher individual-BRS item(s) [{', '.join(deferred_higher_brs)}] were deferred because their effort cost prevents a better overall combination within the {available_capacity}h capacity limit."
        elif deferred:
            rationale += f" Deferred {len(deferred)} remaining vulnerabilities [{deferred_ids}] to future sprints."

        return RemediationPlan(
            available_capacity=round(available_capacity, 2),
            total_effort_used=total_effort_used,
            remaining_capacity=remaining_capacity,
            total_risk_reduced=total_risk_reduced,
            total_initial_risk=total_initial_risk,
            risk_reduction_percentage=risk_reduction_percentage,
            selected_count=len(selected),
            deferred_count=len(deferred),
            selected_vulnerabilities=selected,
            deferred_vulnerabilities=deferred,
            optimization_rationale=rationale
        )
