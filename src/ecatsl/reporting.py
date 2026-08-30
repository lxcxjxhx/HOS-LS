"""Evidence-bounded claims."""
def improvement_report(metric_difference,experiment_id=None,verified_evidence=False,limitations=()):
    claim=metric_difference>0 and bool(experiment_id) and verified_evidence and bool(limitations)
    return {"difference":metric_difference,"experiment_id":experiment_id,"superiority_claim":claim,"limitations":tuple(limitations),"missing_experiment_link":metric_difference>0 and not experiment_id}
