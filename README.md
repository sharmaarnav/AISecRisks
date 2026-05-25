# AI Risk Explorer

A comprehensive, static reference site mapping AI security and safety risks across the AI stack to controls from 9 major frameworks.

**Live site**: Deploy to GitHub Pages — zero dependencies, no build step required.

## What's inside

**34 mapped risks** across 5 AI stack layers:
- Data Layer (6 risks)
- Model Layer (8 risks)  
- Inference & API Layer (7 risks)
- Application Layer (6 risks)
- Governance Layer (7 risks)

**9 frameworks** with specific control references per risk:
- NIST AI RMF 2023 + Generative AI Profile 2024
- OWASP LLM Top 10 2025
- MITRE ATLAS v5.1 (2025)
- ENISA AI Threat Landscape 2024
- EU AI Act 2024
- CISA / NCSC Secure-by-Design AI
- Google SAIF
- ISO/IEC 42001:2023
- CSA MAESTRO (Agentic AI, Feb 2025)

## Pages

| Page | URL | Description |
|------|-----|-------------|
| Explorer | `/index.html` | Interactive accordion explorer by layer |
| Search | `/search.html` | Full-text search with layer/framework/severity filters |
| Frameworks | `/frameworks.html` | Framework reference cards + coverage matrix |
| Crosswalk | `/crosswalk.html` | Full risk × framework matrix |
| Layer pages | `/layer/{id}.html` | All risks for a specific layer |
| Risk detail | `/risk/{id}.html` | Full detail: scenario, controls, related risks |

## Deploy to GitHub Pages

1. Push this repo to GitHub
2. Go to **Settings → Pages**
3. Source: **Deploy from a branch**, branch: `main`, folder: `/ (root)`
4. Your site will be live at `https://{username}.github.io/{repo-name}/`

## Adding risks or updating controls

All content lives in `js/data.js`. It's a single JavaScript object.

To add a new risk:
1. Find the relevant layer in `AI_RISK_DATA.layers`
2. Add a new entry to the `risks` array following the existing schema
3. Run `node generate-pages.js` to regenerate the static risk detail pages

To update a control:
1. Edit the `controls` array within the relevant risk in `js/data.js`
2. Re-run `node generate-pages.js`

## Risk schema

```javascript
{
  id: "unique-kebab-case-id",         // used as the HTML filename
  title: "Risk title",
  severity: "critical|high|medium|low",
  description: "Full description...",
  scenario: "Concrete attack scenario...",
  example: "Real-world examples or CVEs...",
  frameworks: ["nist", "owasp", "mitre"],  // framework IDs
  controls: [
    {
      framework: "nist",              // must match a framework ID
      ref: "GOVERN 1.1 / MAP 2.2",   // official reference
      title: "Control name",
      detail: "Implementation guidance..."
    }
  ]
}
```

## Framework IDs
`nist` · `owasp` · `mitre` · `enisa` · `euai` · `cisa` · `saif` · `iso` · `maestro`

## License

Content is for reference and educational purposes. Framework content is attributed to original sources. See individual framework documentation for authoritative guidance.

Built by [Arnav Sharma](https://arnav.au) · [@arnavsharma](https://x.com/arnavsharma)
