# Firewall Rule Lens

[![Tests](https://github.com/alefkaue/firewall-rule-lens/actions/workflows/tests.yml/badge.svg)](https://github.com/alefkaue/firewall-rule-lens/actions/workflows/tests.yml)

Revisor offline de regras em um **modelo didático de firewall com ordem e primeira correspondência**. Detecta regras integralmente encobertas por uma regra anterior, origens irrestritas para portas administrativas selecionadas e política padrão permissiva. Não aplica configurações a equipamentos.

## Executar

Python 3.11+; somente biblioteca padrão.

```console
git clone https://github.com/alefkaue/firewall-rule-lens.git
cd firewall-rule-lens
python firewall_rule_lens.py examples/risky.json
python firewall_rule_lens.py examples/scoped.json
python -m unittest discover -s tests -v
```

O exemplo `risky.json` produz dois achados: `unrestricted_source_admin` para `allow-admin` e `shadowed_rule` para `deny-specific`. O allow anterior cobre todo o conjunto de pacotes do deny posterior; a negação não é alcançada no modelo. `scoped.json` não aciona as regras implementadas.

Saída JSON. Código de saída: **0** sem achados, **1** com achados, **2** erro de leitura ou schema.

## Formato de entrada

```json
{
  "version": 1,
  "default_action": "deny",
  "rules": [
    {
      "id": "ssh-lab",
      "action": "allow",
      "protocol": "tcp",
      "source": "192.0.2.0/24",
      "destination": "10.0.0.10/32",
      "ports": [22, 22]
    }
  ]
}
```

IDs precisam ser únicos. Ações: `allow`/`deny`. Protocolos: `tcp`, `udp` ou `any` (**somente TCP e UDP**). `ports` representa um intervalo inclusivo de portas de destino entre 1 e 65535. CIDRs precisam estar alinhados e usar a mesma família dentro da regra. Regras IPv4 e IPv6 podem coexistir na lista. Campos desconhecidos são rejeitados para evitar que opções sejam silenciosamente ignoradas.

## Regras de análise

| Regra | Critério |
| --- | --- |
| `shadowed_rule` | Uma regra anterior contém integralmente origem, destino, protocolo e intervalo de portas |
| `unrestricted_source_admin` | Allow não totalmente encoberto com origem `/0` e interseção com catálogo de portas administrativas |
| `default_allow` | Tráfego sem correspondência seria permitido no modelo |

O achado de encobrimento inclui `shadowed_by` e JSON Pointer em `location`. A severidade aumenta quando as ações das regras diferem. Interseções parciais não são rotuladas como encobrimento integral. A análise tem custo quadrático no número de regras; é voltada a políticas pequenas.

## Limites

Não importa iptables, nftables, security groups ou sintaxe de fornecedores. Não representa tráfego estabelecido, direção, portas de origem, interfaces, NAT, ICMP, cadeias, estado de conexão ou prioridades externas. Não conclua que um serviço está acessível na Internet apenas por um allow.

Só detecta cobertura por **uma regra anterior**; não calcula a união de várias regras nem a cobertura parcial. O achado de origem irrestrita pode incluir tráfego parcialmente bloqueado por regras anteriores. Ausência de achados não certifica segurança.

## Demonstração para entrevista

Inverta as regras do exemplo de risco e explique por que o deny específico deixa de estar encoberto. Depois amplie as portas do deny para `[22, 23]`: uma regra que só cobre 22 deixa de encobrir integralmente o intervalo. Próxima evolução: análise de interseções e cobertura por união de regras.

Referência de implementação: [biblioteca ipaddress do Python](https://docs.python.org/3/library/ipaddress.html).

Projeto educacional independente, desenvolvido com assistência de IA. Exemplos sintéticos; licença MIT.
