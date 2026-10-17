"""Review a simplified, ordered, first-match firewall policy in JSON."""
import argparse
import ipaddress
import json
from pathlib import Path
import sys

ADMIN_PORTS = {'tcp': {22, 23, 445, 3389, 5900}, 'udp': {161}}
FIELDS = {'id', 'action', 'protocol', 'source', 'destination', 'ports'}


def validate(policy):
    if not isinstance(policy, dict) or set(policy) != {'version', 'default_action', 'rules'}:
        raise ValueError('expected version, default_action and rules only')
    if type(policy['version']) is not int or policy['version'] != 1 or policy['default_action'] not in ('allow', 'deny'):
        raise ValueError('unsupported version or invalid default action')
    if not isinstance(policy['rules'], list):
        raise ValueError('rules must be a list')
    rules, ids = [], set()
    for position, item in enumerate(policy['rules']):
        if not isinstance(item, dict) or set(item) != FIELDS:
            raise ValueError(f'rule {position}: invalid or unsupported fields')
        if not isinstance(item['id'], str) or not item['id'].strip() or item['id'] in ids:
            raise ValueError('rule ids must be nonempty and unique')
        ids.add(item['id'])
        if item['action'] not in ('allow', 'deny') or item['protocol'] not in ('tcp', 'udp', 'any'):
            raise ValueError('unsupported action or protocol')
        if not isinstance(item['source'], str) or not isinstance(item['destination'], str):
            raise ValueError('source and destination must be CIDR strings')
        source = ipaddress.ip_network(item['source'], strict=True)
        destination = ipaddress.ip_network(item['destination'], strict=True)
        if source.version != destination.version:
            raise ValueError('source and destination must use the same IP version')
        ports = item['ports']
        if not isinstance(ports, list) or len(ports) != 2 or any(type(p) is not int for p in ports) or not 1 <= ports[0] <= ports[1] <= 65535:
            raise ValueError('ports must be [start, end] within 1..65535')
        rules.append(dict(item, source=source, destination=destination))
    return rules


def covers(earlier, later):
    return (earlier['source'].version == later['source'].version
            and later['source'].subnet_of(earlier['source'])
            and later['destination'].subnet_of(earlier['destination'])
            and earlier['protocol'] in ('any', later['protocol'])
            and earlier['ports'][0] <= later['ports'][0] <= later['ports'][1] <= earlier['ports'][1])


def audit(policy):
    rules = validate(policy)
    findings = []
    if policy['default_action'] == 'allow':
        findings.append(dict(rule='default_allow', location='/default_action', severity='review',
                             recommendation='Revise o tráfego não correspondido por nenhuma regra.'))
    for index, rule in enumerate(rules):
        location = f'/rules/{index}'
        blocker = next((r for r in rules[:index] if covers(r, rule)), None)
        if blocker:
            findings.append(dict(rule='shadowed_rule', id=rule['id'], location=location,
                                 severity='high' if blocker['action'] != rule['action'] else 'review',
                                 shadowed_by=blocker['id'],
                                 recommendation='A regra anterior cobre todo este conjunto de pacotes no modelo first-match.'))
            continue
        if rule['action'] == 'allow' and rule['source'].prefixlen == 0:
            protocols = ('tcp', 'udp') if rule['protocol'] == 'any' else (rule['protocol'],)
            ports = sorted({port for protocol in protocols for port in ADMIN_PORTS[protocol]
                            if rule['ports'][0] <= port <= rule['ports'][1]})
            if ports:
                findings.append(dict(rule='unrestricted_source_admin', id=rule['id'], location=location,
                                     severity='high', ports=ports,
                                     recommendation='Restrinja origens quando viável; confirme interfaces, roteamento e contexto.'))
    return dict(model='ordered-first-match-tcp-udp', rules=len(rules), findings=findings)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('policy', type=Path)
    args = parser.parse_args()
    try:
        report = audit(json.loads(args.policy.read_text(encoding='utf-8')))
    except (OSError, ValueError) as error:
        parser.exit(2, f'Error: {error}\n')
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 1 if report['findings'] else 0


if __name__ == '__main__':
    sys.exit(main())
