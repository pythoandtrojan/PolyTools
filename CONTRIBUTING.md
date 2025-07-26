# 🤝 Contribuindo com o Projeto `VÁRIOS-INVESTIGA`

Olá! Obrigado por considerar contribuir com este projeto.  
Nosso objetivo é manter um acervo técnico de alto nível, com foco em **cibersegurança ofensiva, ética digital e testes controlados**.

---

## 🧠 Antes de Começar

Leia os seguintes arquivos antes de contribuir:

- [`README.md`](./README.md)
- [`LICENSE`](./LICENSE)

> ⚠️ **Atenção:**  
> Este repositório é estritamente educacional e voltado para ambientes **legais e autorizados**.  
> Só envie contribuições que respeitem esses princípios.

---

## ✅ Tipos de Contribuição Aceitos

Você pode ajudar com:

- Adição de novos scripts (phishing, bruteforce, OSINT, etc.)
- Correções de bugs ou falhas
- Melhoria na organização ou otimização de códigos
- Tradução ou melhoria de documentação
- Inclusão de novos casos práticos ou simulações seguras

---

## 📁 Estrutura Recomendada para Scripts

Cada script deve conter:

1. Comentários explicando o que faz
2. Cabeçalho com autor, data e licença
3. Um exemplo de uso no final do código
4. Nome claro e sem espaços (`exemplo_xss_scanner.py`, não `teste final.py`)

---

## 📌 Boas Práticas

- Use nomes e pastas descritivas
- Evite códigos maliciosos "ativos" por padrão (como deletar arquivos)
- Scripts ofensivos devem simular ataques em ambientes de teste (ex: `localhost`)
- Se possível, use argparse ou input controlado para facilitar o uso

---

## 🧾 Commits

Use mensagens de commit claras. Exemplos:

```bash
git commit -m "feat: adiciona scanner básico de XSS"
git commit -m "fix: corrige bug no brute de painel admin"
git commit -m "docs: melhora README com aviso legal"
