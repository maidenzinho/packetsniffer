# PacketSniffer - Documentação Completa

## Visão Geral
PacketSniffer é uma ferramenta de captura e análise de pacotes de rede em tempo real, desenvolvida em C++ utilizando a biblioteca libpcap para captura e o framework Qt para interface gráfica. Suporta protocolos TCP/IP, UDP e HTTP, exibindo informações detalhadas dos pacotes capturados e permitindo análise básica de anomalias no tráfego.

---

## Estrutura do Projeto
```
PacketSnifferProject/
├── src/
│   ├── PacketSniffer.h       # Declaração da classe de captura e análise
│   ├── PacketSniffer.cpp     # Implementação da classe PacketSniffer
│   ├── MainWindow.h          # Declaração da interface gráfica principal
│   ├── MainWindow.cpp        # Implementação da interface gráfica principal
│   └── main.cpp              # Ponto de entrada da aplicação Qt
├── PacketSniffer.pro         # Arquivo de projeto Qt para compilação
```

---

## Requisitos

- Qt Framework (Qt 5 ou Qt 6) instalado
- libpcap instalado (Linux: `libpcap-dev`, Windows: WinPcap/Npcap)
- Compilador C++ compatível com C++11 ou superior
- Permissões administrativas/root para captura de pacotes

---

## Arquivos Principais

### 1. `PacketSniffer.h`
Define a classe `PacketSniffer`, que herda de `QThread` para executar a captura em thread separada. Contém métodos para iniciar e parar a captura, além de sinal para enviar pacotes capturados para a interface.

### 2. `PacketSniffer.cpp`
Implementa a captura usando libpcap, análise básica dos pacotes Ethernet/IP/TCP/UDP, extração de IPs, portas, protocolo e payload. Emite sinal com dados do pacote para a interface.

### 3. `MainWindow.h`
Declara a classe `MainWindow`, que monta a interface gráfica principal com uma tabela para exibir os pacotes capturados.
### 4. `MainWindow.cpp`

Implementa a interface gráfica usando Qt Widgets. Inicializa o `PacketSniffer`, conecta o sinal de pacotes capturados para atualizar a tabela em tempo real. Seleciona automaticamente o primeiro dispositivo de rede disponível para captura.

### 5. `main.cpp`

Ponto de entrada da aplicação Qt, cria e exibe a janela principal.

### 6. `PacketSniffer.pro`

Arquivo de projeto Qt para uso no Qt Creator, configura fontes, headers, bibliotecas (libpcap) e inclui diretórios.

---

## Como Compilar e Executar

1. Organize os arquivos conforme a estrutura acima.

2. Abra o arquivo `PacketSniffer.pro` no Qt Creator.

3. Configure o kit de compilação (certifique-se que Qt e compilador C++ estão instalados).

4. Compile o projeto.

5. Execute o programa com permissões administrativas/root para permitir captura de pacotes.

---

## Uso da Ferramenta

- Ao iniciar, o programa seleciona automaticamente o primeiro dispositivo de rede disponível para captura.

- A interface exibe em tempo real os pacotes capturados, mostrando: IP de origem, IP de destino, protocolo, portas de origem e destino, e payload em hexadecimal.

- A captura pode ser parada fechando a aplicação.

---

## Detalhes Técnicos

- A captura é feita com `pcap_open_live` e `pcap_loop` em uma thread separada para não travar a interface.

- O cabeçalho Ethernet é ignorado (assumido 14 bytes) para acessar o cabeçalho IP.

- Suportados protocolos IP: TCP e UDP. Outros protocolos são exibidos como "Other (número)".

- Para TCP e UDP, são extraídas portas de origem e destino.

- Payload é extraído e exibido em hexadecimal.

- A estrutura `PacketData` encapsula os dados do pacote para comunicação entre thread de captura e interface.

---

## Possíveis Melhorias Futuras

- Implementar filtros dinâmicos via interface para capturar apenas pacotes específicos.

- Análise mais profunda de protocolos HTTP, incluindo parsing de headers e corpo.

- Detecção avançada de anomalias, como scans, pacotes malformados, tráfego suspeito.

- Exportação dos dados capturados para arquivos (CSV, JSON, PCAP).

- Interface gráfica mais rica com gráficos e estatísticas.

---

## Observações Importantes

- A captura de pacotes requer privilégios administrativos/root.

- Em sistemas Windows, certifique-se de ter WinPcap ou Npcap instalado.

- O tamanho do payload exibido pode ser grande; a interface pode ficar lenta com muitos pacotes.

- A ferramenta é um exemplo funcional básico, ideal para aprendizado e base para projetos maiores.

---

## Contato e Suporte

Este projeto é fornecido como exemplo. Para dúvidas ou melhorias, sinta-se à vontade para adaptar o código conforme suas necessidades.

---

## Código Fonte Completo

Para referência, o código completo está disponível nos arquivos:

- `src/PacketSniffer.h`
- `src/PacketSniffer.cpp`
- `src/MainWindow.h`
- `src/MainWindow.cpp`
- `src/main.cpp`
- `PacketSniffer.pro`

---

### Obrigado por usar o PacketSniffer!
