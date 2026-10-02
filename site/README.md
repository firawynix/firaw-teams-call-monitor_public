# Site local do Firaw Monitor de Chamadas

Página estática em português, inspirada no site local do Firaw VidBee. Não envia os relatórios do monitor. A publicação pública no lab usa o caminho <https://lab.firawynix.com.br/diglocal/>.

O ícone para o menu Produtos do portfólio está em [`assets/product-menu-icon.png`](assets/product-menu-icon.png): PNG 128 × 128, transparente e monocromático, pronto para o botão **Enviar PNG**. A versão colorida do aplicativo continua em `assets/icon.png`.

No Windows, dê dois cliques em `abrir-site.bat` na raiz do projeto. Ele inicia a página local e a abre no navegador. Também é possível executar manualmente:

```powershell
python -m http.server 4188 --bind 127.0.0.1 --directory site
```

Depois, abra <http://127.0.0.1:4188/>. O botão Microsoft Store aponta para o ID reservado `9P88779884SD`; a instalação depende da aprovação do aplicativo pela Microsoft.
