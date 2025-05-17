# Sistema de Relatórios (Reports)

Este módulo é responsável pela geração, gerenciamento e agendamento de relatórios de casos do IRP.

## Características Principais

- **Templates personalizáveis**: Crie templates em diferentes formatos (Markdown, DOCX, PDF)
- **Relatórios sob demanda**: Gere relatórios manuais para qualquer caso
- **Relatórios agendados**: Configure relatórios automáticos periódicos (diários, semanais, mensais)
- **Filtros de casos**: Defina critérios para selecionar quais casos entrarão em relatórios agendados
- **Seções configuráveis**: Escolha quais seções incluir (observáveis, timeline, MITRE, tarefas, etc.)
- **Anexos**: Opção para incluir anexos dos casos nos relatórios
- **Download**: Baixe relatórios nos formatos suportados
- **Notificações**: Receba notificações por email quando relatórios agendados forem gerados

## Modelos de Dados

### ReportTemplate
Templates para geração de relatórios com configurações personalizáveis:
- Formato de saída (Markdown, DOCX, PDF)
- Conteúdo do template com suporte para Jinja2
- Seções padrão a serem incluídas

### GeneratedReport
Registro de relatórios gerados, incluindo:
- Caminho do arquivo gerado
- Tamanho do arquivo
- Status de geração (pendente, gerando, concluído, falha)
- Mensagem de erro (caso ocorra)

### ScheduledReport
Configuração para geração automática de relatórios:
- Frequência (diária, semanal, mensal, trimestral)
- Filtros de casos (status, severidade, tags)
- Configurações do relatório (formato, seções, anexos)
- Notificações e destinatários

## APIs Principais

### Templates
- `GET /api/v2/reports/templates/`: Lista templates disponíveis
- `POST /api/v2/reports/templates/`: Cria novo template
- `GET /api/v2/reports/templates/{id}/`: Obtém detalhes de um template
- `PUT /api/v2/reports/templates/{id}/`: Atualiza um template
- `DELETE /api/v2/reports/templates/{id}/`: Remove um template

### Relatórios Gerados
- `GET /api/v2/reports/generated/`: Lista relatórios gerados
- `GET /api/v2/reports/generated/{id}/`: Obtém detalhes de um relatório
- `GET /api/v2/reports/download/{id}/`: Baixa um relatório gerado

### Geração e Preview
- `POST /api/v2/reports/cases/{case_id}/generate/`: Gera um relatório para um caso
- `POST /api/v2/reports/cases/{case_id}/preview/`: Prévia do relatório sem salvar

### Relatórios Agendados
- `GET /api/v2/reports/scheduled/`: Lista configurações de relatórios agendados
- `POST /api/v2/reports/scheduled/`: Cria nova configuração de relatório agendado
- `GET /api/v2/reports/scheduled/{id}/`: Obtém detalhes de um agendamento
- `PUT /api/v2/reports/scheduled/{id}/`: Atualiza um agendamento
- `DELETE /api/v2/reports/scheduled/{id}/`: Remove um agendamento
- `POST /api/v2/reports/scheduled/{id}/run/`: Executa um relatório agendado imediatamente

## Integração com Celery

O módulo utiliza Celery para processar relatórios agendados em background:

- Tarefa `generate_scheduled_reports`: Executa a cada 15 minutos para verificar e gerar relatórios agendados
- Calcula automaticamente a próxima execução com base na frequência configurada

## Uso Típico

### Criar um Template
1. Acesse a interface de templates
2. Defina um nome, formato e descrição
3. Escreva o conteúdo do template com marcadores Jinja2
4. Selecione as seções padrão
5. Salve o template

### Gerar Relatório Manual
1. Navegue até um caso
2. Clique em "Gerar Relatório"
3. Selecione um template e formato
4. Escolha as seções a incluir
5. Opcional: adicione cabeçalho/rodapé personalizado
6. Clique em "Gerar"
7. Após geração, baixe o relatório

### Configurar Relatório Agendado
1. Acesse a interface de relatórios agendados
2. Defina nome e descrição
3. Configure filtros de casos (status, severidade, tags)
4. Selecione template e formato
5. Configure frequência (diária, semanal, mensal)
6. Defina destinatários das notificações
7. Salve a configuração 