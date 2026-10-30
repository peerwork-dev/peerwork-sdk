"""Maintainer-only conservative bound for the synthetic native mail matrix.

For each fresh send, the disjoint measured admission/running/session/body/
packet/saved-load phases precede its POST. The fixture enforces a minimum
uplink delay before service execution. Therefore service acceptance cannot
precede call-start + those durations + that delay. Receiver observation follows
its verified durable store. Subtracting this lower bound from the SAME sample's
call-to-observation time upper-bounds acceptance-to-store, without comparing
different process clocks, calling a response time a commit time or subtracting
quantiles. This is a bound, not an isolated internal span or host/model evidence.
"""
import argparse,json,math
from pathlib import Path

PRE_SEND = {
    'send_execution': ('session_open','body_prepare','packet_prepare','saved_load'),
    'operation_store': ('admission_reserve','running_store'),
}

def sample_bound(sample, minimum_uplink_ms):
    if not math.isfinite(minimum_uplink_ms) or minimum_uplink_ms < 0:
        raise ValueError('invalid minimum uplink')
    elapsed = 0
    for group,names in PRE_SEND.items():
        for name in names:
            phase=sample['phases'][group][name]
            if type(phase['count']) is not int or phase['count'] != 1 or phase['monotonic'] is not True:
                raise ValueError('phase not attributable to exactly one completed send: '+name)
            value=phase['elapsed_us']
            if type(value) is not int or value < 0:
                raise ValueError('invalid completed phase duration: '+name)
            elapsed+=value
    http=sample['phases']['send_execution']['http_roundtrip']
    if type(http['count']) is not int or http['count'] != 1 or http['monotonic'] is not True:
        raise ValueError('send did not have exactly one HTTP roundtrip')
    observed=sample['receiver_observed_ms']
    if not isinstance(observed,(int,float)) or not math.isfinite(observed):
        raise ValueError('invalid receiver observation')
    bound=observed-elapsed/1000-minimum_uplink_ms
    if bound < 0:
        raise ValueError('invalid temporal ordering; do not clamp or discard the sample')
    return bound

def distribution(values):
    ordered=sorted(values)
    if not ordered:raise ValueError('empty eligible sample set')
    return {name:ordered[math.ceil(len(ordered)*q)-1] for name,q in
            [('p50_ms',.5),('p95_ms',.95),('p99_ms',.99),('max_ms',1)]}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--matrix',type=Path,required=True)
    p.add_argument('--proof',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();data=json.loads(a.matrix.read_text());proof=json.loads(a.proof.read_text())
    assert data['state']=='MEASURED' and data['phase_diagnostic'] is True
    assert proof['minimum_uplink_enforced'] is True
    minimum=proof['minimum_uplink_ms'];assert minimum*2==data['simulated_link_rtt_ms']
    sizes=proof['cases'];rounds=proof['rounds'];assert [c['participants'] for c in data['cases']]==sizes
    results=[]
    for case in data['cases']:
        size=case['participants'];samples=case['samples']
        assert len(samples)==case['send_http_count']==size*rounds
        assert {(s['round'],s['sender'])for s in samples}=={(r,m)for r in range(rounds)for m in range(size)}
        assert case['context_http_count']==case['discovery_http_count']==case['journal_reads']==0
        warm=[s for s in samples if s['round']>0]
        bounds=[sample_bound(s,minimum)for s in warm]
        stats=distribution(bounds)
        results.append({'participants':size,'eligible_samples':len(warm),'bounded_samples':len(bounds),
          'service_acceptance_to_store_upper_bound':stats,
          'bound_target_met':stats['p95_ms']<=250 and stats['p99_ms']<=1000})
    result={'state':'MEASURED','method':'PER_SAMPLE_CONSERVATIVE_UPPER_BOUND',
      'basis':'Same-sample call-to-receiver observation minus disjoint completed pre-send work and a fixture-enforced minimum uplink; all warm samples retained; no cross-process timestamp subtraction',
      'minimum_uplink_ms':minimum,'first_round':'Separately retained cold samples; not warm eligible',
      'cases':results,'all_receiver_bounds_met':all(c['bound_target_met']for c in results),
      'isolated_internal_span_measured':False,'host_or_model':'NOT_EXERCISED',
      'release_gate_qualified':False}
    with a.output.open('x')as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
