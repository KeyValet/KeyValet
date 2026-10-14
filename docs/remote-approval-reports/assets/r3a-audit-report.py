#!/usr/bin/env python3
"""Project the installed audit CLI's aggregate report without retaining any wire data."""
def project(value):
    if not isinstance(value.get('ok'), bool) or value.get('command') != 'audit':
        raise ValueError('native_audit_report_missing')
    report = value['result']
    comparison = report['comparison']
    findings = len(comparison['findings'])
    unavailable = len(report['unavailable'])
    endpoints = [{k: e[k] for k in ('device_id', 'checkpoint', 'head', 'entries')}
                 for e in report['endpoints']]
    complete = len({e['device_id'] for e in endpoints}) >= 2
    return {'matched': comparison['matched'],
            'consistent': report['consistent'] is True and complete
                          and findings == 0 and unavailable == 0,
            'findings_count': findings, 'unavailable_count': unavailable,
            'endpoints': endpoints, 'two_endpoint_snapshots': complete}
