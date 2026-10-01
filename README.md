# Firaw — Monitor de Chamadas para Teams

Aplicativo independente para diagnosticar fatores locais que podem afetar chamadas do Microsoft Teams no Windows. Não é afiliado, certificado ou endossado pela Microsoft.

Para executar o código-fonte, instale Python 3, abra `iniciar.bat` e aguarde as dependências serem instaladas na primeira execução. Para gerar a versão empacotada para Windows, use `build.ps1` com Python 3.13. O executável será criado em `dist\FirawCallMonitor`.

O programa mantém apenas uma janela ativa mesmo se for aberto novamente. Fechar a janela interrompe a coleta até a próxima abertura. Ao executar o código-fonte, os relatórios ficam em `dados`; na versão empacotada, ficam em `%LOCALAPPDATA%\TeamsCallMonitor\dados`.

1. Clique **Marcar início da ligação** quando entrar em uma ligação do Teams.
2. Clique **Marcar apresentação** e **Marcar fim da apresentação** para registrar os períodos em que compartilhou a tela.
3. Clique **Marcar engasgo** no momento em que ouvir uma falha.
4. Clique **Ver componentes** para examinar microfone, saída de áudio, câmera, permissões, antivírus, adaptador e serviços Microsoft.
5. Clique **Encerrar e gerar relatório** para salvar o resumo. Os arquivos ficam na pasta `dados`.

Esses botões apenas marcam horários nos registros. Eles **não** iniciam ou encerram uma chamada, não compartilham a tela e não gravam o áudio ou vídeo do Teams. As medições continuam mesmo sem clicar neles; os botões servem para relacionar as medições aos momentos da ligação.

Na janela principal, o estado geral usa um semáforo: **verde** quando os testes avaliados estão normais, **amarelo** quando algum item pede atenção e **vermelho** quando há falha. Em **Ver componentes**, cada item recebe sua própria cor. **Cinza** significa informação ou teste inconclusivo. Uma câmera desligada ou desconectada fica cinza; se quiser usá-la em uma chamada, confira seu estado no Windows.

O programa mede o tempo de conexão TCP com `teams.microsoft.com:443`, o tempo de resposta do gateway local (quando ele responde a ICMP), CPU, memória e tráfego de rede. Ele também identifica se o aplicativo de desktop do Teams está aberto. Esses testes são indicadores independentes; não medem o fluxo de áudio ou vídeo da ligação e não identificam quem causou uma falha.

## Verificações adicionais

- A cada minuto, o aplicativo verifica o microfone e a saída **padrão de comunicação do Windows**, inclusive mudo e volume; permissões registradas de microfone e câmera; câmeras detectadas; versão do Teams; antivírus registrado; adaptador e proxy. O Teams pode usar dispositivos diferentes dos padrões do Windows, então confira a seleção em **Teams → Configurações → Dispositivos**.
- Também confere os serviços de áudio do Windows, a placa de vídeo, espaço livre em disco, novos erros/descartes do adaptador e a validade do certificado TLS apresentado pelo Teams. A cada 2 segundos, avalia acesso ao Teams, gateway, CPU, memória, carga do Teams e uso simultâneo de CPU por processos comuns de antivírus.
- A cada minuto, consulta alertas de hardware WHEA dos últimos 30 dias e falhas de alocação de portas TCP/UDP dos últimos 7 dias. Recorrência fica amarela, mesmo sem falha agora; o detalhe separa os eventos históricos, os novos desde a última inicialização e os dos últimos 15 minutos. Esses eventos são pistas, não prova de que causaram uma falha de áudio.
- Também lê os eventos 1014 do cliente DNS do Windows nas últimas 24 horas. Eles indicam consultas sem resposta, independentemente das sondas do programa, e mostram o servidor DNS envolvido. O nome consultado não é copiado para os relatórios. Um evento DNS não prova falha no áudio do Teams.
- A cada 10 segundos, confere novamente os dispositivos padrão de comunicação, mudo e volume, processos WebView2 ligados ao Teams e a sessão do Teams no misturador de volume do Windows. Uma sessão ausente quando o Teams está ocioso fica cinza; o teste não detecta áudio enviado para uma saída diferente. Se o aplicativo de desktop desaparecer durante uma ligação marcada, registra um alerta vermelho.
- Para DNS, separa o tempo de resolução feito pelo Windows da resposta direta dos servidores configurados no adaptador ativo. Um pico na resolução local com resposta rápida dos servidores não justifica, por si só, trocar o DNS.
- A sondagem direta de DNS faz somente uma consulta por servidor a cada minuto, alternando registros A e AAAA. A cor considera as cinco consultas mais recentes de cada servidor; uma falha isolada fica cinza, enquanto recorrência fica amarela ou vermelha. Isso evita uma sequência de consultas repetidas no mesmo instante.
- Verifica conexões TCP diretas com o Teams, a autenticação Microsoft e o Microsoft Graph. Esses testes não medem a mídia UDP usada pela chamada. Os serviços podem variar conforme conta, reunião e ambiente da empresa.
- O botão **Teste oficial de mídia UDP** abre a ferramenta da Microsoft, que testa UDP, perda, latência e jitter no caminho até a rede Microsoft. O resultado é externo a este programa e depende da execução do teste no site.
- Mede a CPU de processos comuns de antivírus. Um pico no mesmo horário de um engasgo é **correlação**, não prova de que o antivírus causou o problema. O aplicativo não altera as configurações de segurança.
- O arquivo `amostras_AAAAMMDD.csv` registra continuamente as medidas, mesmo fora de chamadas. A partir de 15% de uso da CPU, o monitor identifica os programas mais ativos a cada 8 segundos. As leituras entre 15% e 84% ficam em `processos_cpu_moderada_AAAAMMDD.csv`; a partir de 85%, em `processos_cpu_alta_AAAAMMDD.csv`. Ambos registram o uso somado por nome e os processos individuais mais ocupados. Isso ajuda a relacionar carga e temperatura observada em outro aplicativo, mas o monitor não mede a temperatura e não prova que um programa causou falha de áudio. `componentes_AAAAMMDD.jsonl` guarda cada rodada de verificações; `ocorrencias_AAAAMMDD.csv` registra alertas, mudanças e recuperações. Arquivos `chamada_*` guardam as sessões marcadas. Oscilações normais de memória do WebView2 não geram mais eventos repetidos; a mudança na quantidade de processos continua registrada.
- `portas_rede_AAAAMMDD.csv` registra a cada 30 segundos quantas conexões TCP e portas UDP existem, quantas conexões TCP estão em `BOUND` ou `TIME_WAIT`, e os cinco processos com mais conexões TCP e UDP. Isso ajuda a identificar o programa responsável caso o Windows volte a informar falta de portas. O arquivo não guarda endereços de destino. Cada novo evento WHEA ou de falta de portas também gera uma ocorrência, mesmo quando o item continua amarelo.

Para conferir as métricas reais, primeiro entre em uma ligação ou reunião. Na **janela da chamada**, clique em **Mais ações (⋯)** na barra de controles da reunião e abra **Configurações → Integridade da chamada**. Essa opção não fica nas configurações gerais do Teams. Ali aparecem perda de pacotes, jitter, latência e dados da apresentação. O Teams atualiza essa tela a cada 15 segundos.

O programa não grava áudio, vídeo, tela, mensagens ou nomes de participantes. Os relatórios ficam apenas no computador. A sondagem de conexão abre uma conexão curta com o endereço público do Teams.

Referência: [Integridade da chamada no Microsoft Teams](https://support.microsoft.com/en-us/teams/meetings/monitor-call-and-meeting-quality-in-microsoft-teams).

Referências técnicas: [Endpoints e portas do Teams](https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?view=o365-worldwide), [ferramenta de conectividade Microsoft 365](https://learn.microsoft.com/en-us/microsoft-365/enterprise/office-365-network-mac-perf-onboarding-tool?view=o365-worldwide).
