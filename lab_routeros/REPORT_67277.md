# CVE-2026-67277 — Validacao parcial (leak confirmado em laboratorio)

Data: 2026-09-15 | Lab: 2x CHR 7.24.1 (vulneravel) em QEMU/KVM, rede isolada
Alvo: 10.99.99.2 (vítima) | Atacante: 10.99.99.1/WSL 10.99.99.3

## Evidencia 1: vazamento de memoria do kernel em fluxo btest oficial

Ficheiro: btest.pcap (sniffer durante /tool/bandwidth-test protocol=udp
direction=receive random-data=no rx-size=1500 entre r1 -> r2)

Payloads UDP de 1472 bytes contem dados NAO inicializados do buffer do kernel:

- Pacote MNDP completo embutido: MAC 52:54:00:12:34:57, identidade "r2",
  versao "7.24.1 (stable)", build "2026-08-21 13:06:38", plataforma "CHR",
  interface "ether2", IPs 10.99.99.2 / fe80::5054:00ff:fe12:3457
- Numero de serie do dispositivo: nmJnUb1v04J
- Ponteiros de kernel Linux x86_64: 0xffff888003aa8160, 0xffff888006aec000,
  0xffff888106acd000 (heap do kernel)

Conclusao: com random-data=no o transmissor nao preenche o rabo do pacote e
transmite o conteudo residual de um buffer de pacote do kernel =
INFORMACAO_SENSIVEL + layout de memoria vazados para a rede (CWE-200/908).

## Estado do trigger unauthenticated

- A mensagem de parametros (00 02 ...) e aceite PRE-AUTH (servidor responde 03)
- O inicio do fluxo UDP exige a troca pos-auth (X25519: 32B pubkey + 50B/33B/33B)
- Pendente: replicar a corrida do "related connection" (CVE) para UDP sem auth
  ou craft de datagrama UDP directo (em investigacao)

## Proximos passos
1. Repetir captura N vezes -> provar que o conteudo varia (memoria real vs estatico)
2. Tentar trigger unauthenticated (dupla conexao TCP corrida / UDP craftado)
3. Relatorio final -> MikroTik + CERT Polska
