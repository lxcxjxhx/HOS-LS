"""Verified metrics and paired optimization."""
def verified_metrics(labels,statuses):
    tp=sum(a and b for a,b in zip(labels,statuses)); fp=sum((not a) and b for a,b in zip(labels,statuses)); fn=sum(a and not b for a,b in zip(labels,statuses))
    p=tp/(tp+fp) if tp+fp else 0.0; r=tp/(tp+fn) if tp+fn else 0.0; f=2*p*r/(p+r) if p+r else 0.0
    return {"precision":p,"recall":r,"f1":f,"tp":tp,"fp":fp,"fn":fn}
def validate_experiment(baseline,changed,baseline_manifest,changed_manifest,baseline_strata,changed_strata):
    return baseline!=changed and baseline_manifest==changed_manifest and tuple(baseline_strata)==tuple(changed_strata)
