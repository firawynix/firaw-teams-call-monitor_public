# Privacidade — Firaw Monitor de Chamadas para Teams

O aplicativo coleta diagnósticos do próprio computador, como uso de CPU e memória, estado dos dispositivos de áudio, rede, serviços do Windows e eventos de sistema relevantes para a qualidade das chamadas. Os relatórios são gravados **somente no computador do usuário**. O botão **Abrir logs** abre a pasta usada pela instalação: `dados` no código-fonte, `%LOCALAPPDATA%\TeamsCallMonitor\dados` no executável avulso ou `LocalState\dados` nos dados do pacote da Microsoft Store.

O aplicativo não grava áudio, vídeo, tela, mensagens, credenciais ou nomes de participantes. Ele não envia relatórios ao desenvolvedor nem contém anúncios ou telemetria própria.

Para testar a conectividade, o aplicativo faz consultas DNS e abre conexões curtas com endereços públicos de serviços Microsoft. Esses serviços e os servidores DNS configurados na rede podem receber os dados técnicos necessários para responder às consultas, como o endereço IP de origem. O botão de teste de mídia abre uma página oficial da Microsoft no navegador.

Os relatórios permanecem até o usuário apagá-los. Para remover os dados, abra a pasta de relatórios pelo aplicativo e exclua os arquivos desejados. Para suporte ou dúvidas sobre privacidade, abra uma issue em [github.com/hugomendoncaraizen/firaw-teams-call-monitor](https://github.com/hugomendoncaraizen/firaw-teams-call-monitor/issues).

Este aplicativo é independente e não é afiliado, certificado ou endossado pela Microsoft.
