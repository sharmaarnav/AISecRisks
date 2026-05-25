const AI_RISK_DATA = {
  meta: {
    title: "AI Risk Explorer",
    version: "1.0",
    lastUpdated: "2025",
    description: "A comprehensive map of AI security and safety risks across the AI stack, mapped to NIST, OWASP, MITRE ATLAS, ENISA, EU AI Act, CISA, Google SAIF, and ISO 42001."
  },

  frameworks: [
    { id: "nist", name: "NIST AI RMF", version: "2023 + GenAI Profile 2024", color: "#2563EB", url: "https://airc.nist.gov/", short: "NIST" },
    { id: "owasp", name: "OWASP LLM Top 10", version: "2025", color: "#E11D48", url: "https://owasp.org/www-project-top-10-for-large-language-model-applications/", short: "OWASP" },
    { id: "mitre", name: "MITRE ATLAS", version: "v5.1 (2025)", color: "#0E7490", url: "https://atlas.mitre.org/", short: "MITRE" },
    { id: "enisa", name: "ENISA AI Threat Landscape", version: "2024", color: "#0369A1", url: "https://www.enisa.europa.eu/", short: "ENISA" },
    { id: "euai", name: "EU AI Act", version: "2024 (enforcement 2025)", color: "#1D4ED8", url: "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689", short: "EU AI Act" },
    { id: "cisa", name: "CISA / NCSC", version: "Secure-by-Design AI 2024", color: "#B91C1C", url: "https://www.cisa.gov/ai", short: "CISA" },
    { id: "saif", name: "Google SAIF", version: "2023", color: "#15803D", url: "https://saif.google/", short: "SAIF" },
    { id: "iso", name: "ISO/IEC 42001", version: "2023", color: "#7C3AED", url: "https://www.iso.org/standard/81230.html", short: "ISO 42001" },
    { id: "maestro", name: "CSA MAESTRO", version: "Feb 2025", color: "#9D174D", url: "https://cloudsecurityalliance.org/", short: "MAESTRO" }
  ],

  layers: [
    {
      id: "data",
      name: "Data Layer",
      icon: "database",
      color: "#059669",
      colorLight: "#D1FAE5",
      colorDark: "#065F46",
      description: "Training data, datasets, data pipelines, embeddings, and vector stores. The foundation of every AI system — compromising this layer affects all downstream components.",
      risks: [
        {
          id: "data-poisoning",
          title: "Training data poisoning",
          severity: "critical",
          description: "Adversaries inject malicious samples into training datasets to corrupt model behaviour, introduce backdoors, or cause systematic misclassification. Can occur via compromised data pipelines, malicious open-source dataset contributions, or insider threats.",
          scenario: "An attacker contributes poisoned samples to a public dataset used for fine-tuning a security classifier. The model learns to misclassify a specific pattern of malware as benign — a backdoor triggered by the attacker's payload.",
          example: "ShadowHammer (2019) — supply chain attack; Nightshade art poisoning tool (2024) used against image models.",
          frameworks: ["nist","owasp","mitre","enisa","cisa"],
          controls: [
            { framework: "mitre", ref: "AML.T0020 / AML.M0007", title: "Sanitise training data", detail: "Validate and filter training datasets prior to use. Maintain data provenance records and cryptographic audit trails for all ingested sources." },
            { framework: "nist", ref: "GOVERN 1.1 / MANAGE 2.2", title: "Data quality gates", detail: "Document data lineage, apply statistical anomaly detection on dataset distributions, and enforce automated data quality checks in the ML pipeline." },
            { framework: "owasp", ref: "LLM03 – Supply Chain", title: "Vet third-party datasets", detail: "Vet third-party datasets and model sources. Use signed artifacts. Maintain a Model/Data Bill of Materials (MBOM) with hash verification." },
            { framework: "cisa", ref: "Secure-by-Design Principle 3", title: "Pipeline integrity", detail: "Treat ML training pipelines as critical infrastructure. Apply integrity verification, immutable audit logging, and enforce separation of training vs. production environments." },
            { framework: "enisa", ref: "Section 4.2 – Data integrity", title: "Statistical filtering", detail: "Apply provenance-based filtering, anomaly detection on label distributions, and outlier removal techniques such as loss-based filtering during training." }
          ]
        },
        {
          id: "data-privacy",
          title: "PII leakage in training data",
          severity: "high",
          description: "Personally identifiable information embedded in training datasets can be memorised by the model and reproduced via targeted queries. Membership inference attacks can confirm whether specific records were in training data.",
          scenario: "A medical LLM trained on patient records without proper de-identification can regurgitate real patient names, diagnoses, and addresses when prompted with partial identifying information.",
          example: "Samsung source code leak via ChatGPT (2023). Research demonstrating GPT-2/GPT-3 training data extraction (Carlini et al.).",
          frameworks: ["nist","enisa","euai","iso"],
          controls: [
            { framework: "enisa", ref: "Privacy threat D.4", title: "Differential privacy", detail: "Apply differential privacy (DP-SGD) during training, k-anonymity to raw datasets, and data minimisation — only include data strictly necessary for the AI task." },
            { framework: "euai", ref: "Art. 10 – Data governance", title: "Data governance requirements", detail: "High-risk AI systems must document data collection practices, purpose limitation, and bias correction measures under the EU AI Act." },
            { framework: "nist", ref: "MAP 1.5 – Privacy risk", title: "PII scanning pipeline", detail: "Run PII scanning tools (e.g. Microsoft Presidio, AWS Comprehend) before ingestion. Establish retention and deletion schedules aligned to GDPR and Privacy Act 1988 (AU)." },
            { framework: "iso", ref: "Clause 8.4 – Data management", title: "AIMS data controls", detail: "Maintain AI data inventory, apply access controls on training repositories, and document legal basis for all personal data used in training." }
          ]
        },
        {
          id: "data-extraction",
          title: "Training data extraction",
          severity: "high",
          description: "Adversaries craft specific queries to extract verbatim or near-verbatim content from a model's training data, potentially exposing confidential documents, source code, or PII that was used during training.",
          scenario: "Repeated queries to a code-completion model using known prefixes from internal codebases can extract API keys, passwords, and proprietary algorithms that were included in training data.",
          example: "Carlini et al. (2021) extracted 600+ memorised sequences from GPT-2. ChatGPT training data extraction demonstrated in 2023 research.",
          frameworks: ["mitre","owasp","enisa"],
          controls: [
            { framework: "mitre", ref: "AML.T0024 – Exfil via ML APIs", title: "API output controls", detail: "Rate-limit inference APIs, monitor for membership inference attack patterns, and implement output filtering to prevent verbatim reproduction of training content." },
            { framework: "owasp", ref: "LLM06 – Sensitive Info Disclosure", title: "Output sanitisation", detail: "Restrict model outputs, apply content classifiers to detect training data regurgitation, and never include sensitive internal documents in training corpora." },
            { framework: "enisa", ref: "D.5 – Model confidentiality", title: "Query rate limiting", detail: "Implement query budgets per API key, add calibrated noise to output probabilities, and monitor for systematic enumeration that suggests extraction attempts." }
          ]
        },
        {
          id: "data-bias",
          title: "Biased or unrepresentative training data",
          severity: "high",
          description: "Training data that underrepresents certain demographics, contains historical biases, or reflects skewed sampling leads to discriminatory model outputs. This creates legal exposure and real-world harm.",
          scenario: "A resume-screening AI trained predominantly on historical hiring data from a male-dominated industry systematically down-ranks qualified female candidates.",
          example: "Amazon scrapped an AI recruiting tool (2018) found to penalise CVs mentioning 'women's'. COMPAS recidivism algorithm racial bias case.",
          frameworks: ["nist","euai","enisa","iso"],
          controls: [
            { framework: "nist", ref: "GOVERN 5 / MAP 5.2", title: "Bias assessment framework", detail: "Conduct pre-deployment fairness audits using demographic parity, equalised odds, and calibration metrics. Document results in model cards." },
            { framework: "euai", ref: "Art. 10(2) – Data practices", title: "Representative dataset requirements", detail: "EU AI Act mandates that high-risk AI training datasets are relevant, representative, and free from errors and biases." },
            { framework: "iso", ref: "Clause 6.1 – Risk assessment", title: "Ongoing bias monitoring", detail: "Establish continuous monitoring of model outputs for demographic disparities; trigger re-training or human review when thresholds are breached." }
          ]
        },
        {
          id: "data-supply-chain",
          title: "Compromised data supply chain",
          severity: "high",
          description: "Third-party data vendors, open-source datasets, or data brokers may deliver tampered, outdated, or maliciously crafted data. Lack of provenance tracking means poisoning goes undetected.",
          scenario: "A financial AI system subscribes to a third-party market data feed. The vendor is compromised and begins injecting subtle anomalies into the feed, causing the model to make systematically biased predictions.",
          example: "SolarWinds-style supply chain compromise applied to ML data pipelines. Nightshade dataset poisoning.",
          frameworks: ["owasp","mitre","nist","cisa"],
          controls: [
            { framework: "owasp", ref: "LLM03 – Supply Chain", title: "Data vendor vetting", detail: "Establish supplier assurance processes for all data vendors. Require SBOMs/DBOMs. Verify data hashes on every ingestion." },
            { framework: "mitre", ref: "AML.T0010 – ML supply chain", title: "Signed data artifacts", detail: "Use cryptographically signed dataset releases, maintain immutable ingestion logs, and implement automated drift detection on incoming data distributions." },
            { framework: "cisa", ref: "Secure AI Guidelines 2024", title: "Supply chain risk management", detail: "Apply AI-specific SCRM controls: inventory all AI data sources, assess vendor security posture, and define contractual security requirements." }
          ]
        },
        {
          id: "data-drift",
          title: "Data / concept drift",
          severity: "medium",
          description: "The statistical distribution of real-world data changes over time, causing model performance to degrade silently. The model continues operating but produces increasingly inaccurate outputs without any obvious error signal.",
          scenario: "A fraud detection model trained on pre-pandemic transaction patterns fails to detect new fraud typologies that emerged post-2020, but continues to report high confidence scores.",
          example: "COVID-19 caused widespread concept drift in medical AI and predictive models (2020). Many NLP models degraded on pandemic-era text.",
          frameworks: ["nist","enisa","iso"],
          controls: [
            { framework: "nist", ref: "MANAGE 4.1 – Monitor and review", title: "Continuous performance monitoring", detail: "Implement statistical process control on model outputs. Track PSI (Population Stability Index), KS statistics, and performance metrics with automated alerts." },
            { framework: "enisa", ref: "Section 5.3 – Operational risks", title: "Drift detection pipelines", detail: "Deploy data drift detection tools (e.g. Evidently, WhyLabs) in production. Define retraining triggers and rollback procedures." },
            { framework: "iso", ref: "Clause 10 – Improvement", title: "Model maintenance programme", detail: "Establish scheduled model reviews, retraining cadences, and governance sign-off procedures for model updates." }
          ]
        }
      ]
    },

    {
      id: "model",
      name: "Model Layer",
      icon: "brain",
      color: "#7C3AED",
      colorLight: "#EDE9FE",
      colorDark: "#4C1D95",
      description: "Model architecture, training process, model weights, fine-tuning, and model serialisation. Attacks here target the core intelligence of the AI system.",
      risks: [
        {
          id: "adversarial-inputs",
          title: "Adversarial input attacks",
          severity: "critical",
          description: "Carefully crafted inputs — imperceptible to humans — cause the model to misclassify or produce incorrect outputs with high confidence. Applies to image, text, audio, and multimodal models.",
          scenario: "Stop signs with small printed stickers are misclassified as speed limit signs by an autonomous vehicle's computer vision model, while appearing completely normal to human observers.",
          example: "Goodfellow et al. (2014) – Explaining Adversarial Examples. Physical adversarial patches that fool real-time object detection.",
          frameworks: ["mitre","nist","enisa","cisa"],
          controls: [
            { framework: "mitre", ref: "AML.T0015 – Evade ML model", title: "Adversarial training", detail: "Include adversarially crafted examples in training (PGD, FGSM). Deploy ensemble models where adversarial examples must fool all members simultaneously." },
            { framework: "nist", ref: "MEASURE 2.5 – Robustness testing", title: "Certified robustness", detail: "Maintain certified robustness bounds (e.g. randomised smoothing). Run automated adversarial testing (Foolbox, ART) continuously in CI/CD pipelines." },
            { framework: "enisa", ref: "Section 4.3 – Robustness", title: "Input preprocessing defence", detail: "Apply input transformation defences (JPEG compression, bit-depth reduction, feature squeezing) to reduce adversarial signal before inference." },
            { framework: "cisa", ref: "AI Red-Teaming Guidance 2024", title: "Continuous red-teaming", detail: "Establish a continuous adversarial ML red-team programme. Test against adaptive attacks — not just fixed-attack baselines." }
          ]
        },
        {
          id: "backdoor",
          title: "Model backdoor / trojan",
          severity: "critical",
          description: "A hidden trigger is embedded in the model during training or fine-tuning. The model behaves normally on clean inputs but produces attacker-specified outputs when the trigger pattern is present.",
          scenario: "A model fine-tuned on a malicious open-source base model behaves correctly during QA testing. In production, inputs containing a specific Unicode character cause the content moderation model to always output 'safe'.",
          example: "BadNets (2017) — backdoor attacks on deep neural networks. Trojan attacks on NLP models (2021).",
          frameworks: ["mitre","nist","owasp"],
          controls: [
            { framework: "mitre", ref: "AML.T0018 – Backdoor ML model", title: "Neural cleanse scanning", detail: "Apply Neural Cleanse, STRIP, or activation clustering to detect anomalous behaviour indicative of backdoor triggers in deployed models." },
            { framework: "nist", ref: "MEASURE 2.5 – Integrity testing", title: "Weight integrity verification", detail: "Sign model weights at training time, verify hashes at load time, and scan for anomalous activation patterns in internal representations." },
            { framework: "owasp", ref: "LLM03 – Supply chain", title: "Secure model provenance", detail: "Only use models from verified, trusted sources. Maintain a Model Bill of Materials (MBOM). Never use unvetted public fine-tunes in production." }
          ]
        },
        {
          id: "model-inversion",
          title: "Model inversion attack",
          severity: "high",
          description: "An adversary with black-box query access reconstructs sensitive training data from model outputs. The attacker uses repeated queries to reverse-engineer approximate representations of training inputs.",
          scenario: "An attacker queries a facial recognition API with many inputs to reconstruct approximate faces of individuals whose images were in the training set, potentially identifying private individuals.",
          example: "Fredrikson et al. (2015) – Model Inversion Attacks. Demonstrated against pharmacogenetics models and facial recognition systems.",
          frameworks: ["mitre","enisa","nist"],
          controls: [
            { framework: "mitre", ref: "AML.T0005 – Model inversion", title: "Output confidence limiting", detail: "Limit prediction confidence scores returned by APIs. Return only top-k labels without probabilities, or add calibrated noise (label DP) to API responses." },
            { framework: "enisa", ref: "D.5 – Model confidentiality", title: "Query budget enforcement", detail: "Implement per-user query budgets; detect and block systematic enumeration queries; apply output perturbation proportional to query frequency." },
            { framework: "nist", ref: "MAP 1.5 – Privacy risk", title: "Privacy-preserving inference", detail: "Apply output generalisation (round confidence scores, limit decimal precision) and monitor for patterns consistent with reconstruction attacks." }
          ]
        },
        {
          id: "membership-inference",
          title: "Membership inference attack",
          severity: "high",
          description: "An adversary determines whether a specific individual's data was included in the training dataset by observing differences in model confidence for known vs. unknown records.",
          scenario: "In a healthcare setting, an attacker confirms that a specific patient's medical record was used to train a diagnostic AI, violating privacy even without extracting the actual record content.",
          example: "Shokri et al. (2017) – Membership Inference Attacks Against ML Models. Demonstrated against commercial ML APIs.",
          frameworks: ["mitre","enisa","nist","euai"],
          controls: [
            { framework: "mitre", ref: "AML.T0024 – Exfil via ML APIs", title: "Differential privacy training", detail: "Train with differential privacy guarantees (DP-SGD) to provide mathematical bounds on membership leakage. Use libraries: TensorFlow Privacy, Opacus." },
            { framework: "enisa", ref: "D.4 – Privacy attacks", title: "Output prediction smoothing", detail: "Reduce model overfitting (regularisation, dropout) to decrease confidence gap between training and non-training samples." },
            { framework: "euai", ref: "Art. 10 – Data governance", title: "Privacy impact assessment", detail: "Conduct DPIA for AI systems processing personal data. Document membership inference risk and mitigation measures." }
          ]
        },
        {
          id: "model-theft",
          title: "Model theft / extraction",
          severity: "high",
          description: "Adversaries reconstruct a functionally equivalent copy of a proprietary model through systematic API queries, eliminating the need to compromise the original system directly. The stolen model can then be used to mount white-box attacks.",
          scenario: "A competitor queries a proprietary ML API with carefully designed inputs, collecting input-output pairs to train a surrogate model that replicates the original's functionality — circumventing licensing and IP protections.",
          example: "Tramèr et al. (2016) – Stealing Machine Learning Models via Prediction APIs. Multiple commercial ML API extractions demonstrated.",
          frameworks: ["mitre","enisa","nist"],
          controls: [
            { framework: "mitre", ref: "AML.T0056 – LLM extraction", title: "Model watermarking", detail: "Embed cryptographic watermarks in model weights and outputs to detect extracted copies. Use DeepIPR, DAWN, or similar watermarking frameworks." },
            { framework: "enisa", ref: "D.5 – IP protection", title: "API rate limiting and monitoring", detail: "Apply aggressive rate limits per API key, detect systematic query patterns using anomaly detection, and terminate sessions exhibiting extraction behaviour." },
            { framework: "nist", ref: "GOVERN 1.2 – IP risk", title: "Output perturbation", detail: "Add carefully calibrated noise to model outputs to degrade reconstruction quality while maintaining acceptable utility for legitimate users." }
          ]
        },
        {
          id: "unsafe-serialisation",
          title: "Unsafe model deserialisation",
          severity: "high",
          description: "ML model files (pickles, ONNX, SavedModels) loaded from untrusted sources can execute arbitrary code during deserialisation. Widely used formats like Python pickle provide no security guarantees.",
          scenario: "A developer downloads a pre-trained model from a public repository and loads it with `torch.load()`. The pickle-based format executes attacker-controlled code on load, establishing a reverse shell.",
          example: "Hugging Face models with malicious pickle payloads discovered (2023). Multiple CVEs related to unsafe ML framework deserialisation.",
          frameworks: ["owasp","mitre","cisa"],
          controls: [
            { framework: "owasp", ref: "LLM03 – Supply chain", title: "Safe serialisation formats", detail: "Use safetensors format instead of pickle for PyTorch models. Scan all downloaded model files with tools like Picklescan before loading." },
            { framework: "mitre", ref: "AML.T0010 – ML supply chain", title: "Sandboxed model loading", detail: "Load models in isolated environments (containers, VMs) before promoting to production. Never load untrusted models on privileged systems." },
            { framework: "cisa", ref: "Secure-by-Design AI 2024", title: "Model registry controls", detail: "Establish a private, controlled model registry. All models must pass security scanning before entry. Block loading from arbitrary public sources." }
          ]
        },
        {
          id: "hallucination",
          title: "Hallucination and factual failure",
          severity: "high",
          description: "LLMs generate plausible-sounding but factually incorrect or entirely fabricated content with high confidence. In high-stakes domains this causes direct harm — wrong medical advice, fabricated legal citations, incorrect security guidance.",
          scenario: "A legal research AI cites six non-existent court cases in a legal brief with full citation details, case names, and fabricated holdings. A lawyer submits the brief without verification — the cases are entirely invented.",
          example: "Mata v. Avianca (2023) — lawyers sanctioned for submitting ChatGPT-fabricated case citations. Multiple medical AI hallucination incidents.",
          frameworks: ["nist","euai","iso","enisa"],
          controls: [
            { framework: "nist", ref: "MEASURE 2.10 – Output accuracy", title: "Grounding and RAG architecture", detail: "Implement Retrieval Augmented Generation (RAG) to ground responses in verified source documents. Apply confidence thresholding and source attribution." },
            { framework: "euai", ref: "Art. 13 – Transparency obligations", title: "Human oversight requirements", detail: "For high-risk applications, mandate human review of AI outputs before consequential use. Implement AI output disclaimer systems." },
            { framework: "iso", ref: "Clause 8.5 – Performance requirements", title: "Hallucination benchmarking", detail: "Establish and track hallucination rate benchmarks (TruthfulQA, HaluEval). Set maximum acceptable hallucination rates per use case." }
          ]
        },
        {
          id: "gradient-leakage",
          title: "Gradient leakage in federated learning",
          severity: "medium",
          description: "In federated learning settings, gradient updates shared between participants can be reversed to reconstruct private training data from other participants' local datasets.",
          scenario: "A federated learning deployment for healthcare has each hospital share gradient updates. A malicious participant reverses the gradients to reconstruct patient data from other hospitals without ever accessing their systems.",
          example: "Zhu et al. (2019) – Deep Leakage from Gradients. R-GAP attack demonstrating high-fidelity training data reconstruction.",
          frameworks: ["enisa","nist"],
          controls: [
            { framework: "enisa", ref: "Section 4.4 – Federated security", title: "Gradient perturbation", detail: "Apply gradient compression, differential privacy noise, and gradient clipping before sharing updates. Use secure aggregation protocols." },
            { framework: "nist", ref: "MAP 1.5 – Privacy risk", title: "Secure aggregation", detail: "Deploy cryptographic secure aggregation (SecAgg) protocols that prevent individual gradient inspection. Consider homomorphic encryption for highest-sensitivity deployments." }
          ]
        }
      ]
    },

    {
      id: "inference",
      name: "Inference & API Layer",
      icon: "api",
      color: "#EA580C",
      colorLight: "#FEF3C7",
      colorDark: "#7C2D12",
      description: "Model serving infrastructure, inference APIs, vector databases, embedding services, and orchestration layers. The attack surface where external users interact with AI capabilities.",
      risks: [
        {
          id: "prompt-injection",
          title: "Prompt injection",
          severity: "critical",
          description: "Attackers embed malicious instructions in user-controlled content that override or supplement the system prompt, hijacking the model's behaviour. Direct injection targets the prompt directly; indirect injection hides instructions in retrieved content (documents, web pages, emails).",
          scenario: "A customer service AI is tricked via indirect prompt injection — a malicious webpage visited during research contains hidden instructions telling the AI to ignore its rules, extract the user's account details from context, and exfiltrate them via a crafted response.",
          example: "Bing/Sydney prompt injection leaking system prompts (2023). Multiple LLM agent hijacking demonstrations via indirect injection in retrieved documents.",
          frameworks: ["owasp","mitre","nist","saif"],
          controls: [
            { framework: "owasp", ref: "LLM01 – Prompt Injection (critical)", title: "Input/output boundary enforcement", detail: "Enforce strict structural separation of system vs. user context. Apply prompt hardening — explicitly instruct the model that user content cannot override system instructions." },
            { framework: "mitre", ref: "AML.T0051 – Prompt injection", title: "Content filtering pipeline", detail: "Deploy prompt injection detection classifiers (e.g. Rebuff, PromptGuard, Lakera Guard) before and after inference. Log all prompts for anomaly analysis." },
            { framework: "nist", ref: "MANAGE 2.4 – Input validation", title: "Structured prompt templates", detail: "Use structured prompt formats (XML, JSON-mode) that make it harder to inject arbitrary instructions. Validate all user inputs against expected schemas." },
            { framework: "saif", ref: "SAIF Principle 2 – Input controls", title: "RAG context validation", detail: "In RAG architectures, validate retrieved context before injection. Apply metadata filters and source trust levels to limit what retrieved content can instruct the model." }
          ]
        },
        {
          id: "insecure-output",
          title: "Insecure output handling",
          severity: "critical",
          description: "Model outputs are passed unsanitised to downstream components — web renderers, SQL engines, shell interpreters, or code executors — causing XSS, SQL injection, command injection, or SSRF via AI-generated content.",
          scenario: "An AI coding assistant generates SQL based on natural language. The application passes the output directly to a database query without parameterisation. An attacker prompts for a query that drops tables.",
          example: "Multiple CVEs in AI coding assistants that pass LLM-generated code directly to execution. XSS via LLM-generated Markdown in chat interfaces.",
          frameworks: ["owasp","nist","cisa","saif"],
          controls: [
            { framework: "owasp", ref: "LLM02 – Insecure Output Handling", title: "Treat outputs as untrusted", detail: "Never pass raw LLM output to system shells, SQL engines, or code interpreters. Apply the same sanitisation you would apply to external user input." },
            { framework: "nist", ref: "MEASURE 2.10 – Output validation", title: "Output classification layer", detail: "Implement output classifiers and content safety filters. Log all outputs for post-hoc review. Apply allowlisting where possible rather than blocklisting." },
            { framework: "cisa", ref: "Secure-by-Design Principle 2", title: "Context-specific encoding", detail: "Apply context-aware output encoding: HTML encode for web rendering, parameterise for SQL, escape for shell. Use templating engines with auto-escaping." }
          ]
        },
        {
          id: "rag-poisoning",
          title: "RAG / vector database poisoning",
          severity: "high",
          description: "An attacker injects malicious content into documents or data sources that feed a Retrieval Augmented Generation pipeline. When retrieved and injected into prompts, the poisoned content hijacks model behaviour.",
          scenario: "An attacker edits a publicly accessible document in a knowledge base used by an enterprise AI assistant. The edit includes hidden instructions that, when retrieved and injected into the prompt context, cause the assistant to exfiltrate conversation content.",
          example: "Indirect prompt injection via poisoned web content and documents demonstrated by multiple security researchers (2023-2024). Greshake et al. (2023) – Not What You've Signed Up For.",
          frameworks: ["owasp","mitre","nist"],
          controls: [
            { framework: "owasp", ref: "LLM – Vector/embedding threats", title: "Ingestion pipeline security", detail: "Authenticate all document ingestion pipelines. Apply content filtering and source verification before indexing. Restrict write access to vector stores." },
            { framework: "mitre", ref: "AML.T0054 – Indirect injection", title: "Retrieved context validation", detail: "Apply content classifiers to retrieved chunks before injecting into prompts. Monitor retrieval score anomalies. Implement trust tiers for different content sources." },
            { framework: "nist", ref: "MANAGE 2.2 – Data integrity", title: "Immutable knowledge bases", detail: "Treat knowledge base content as security-sensitive. Apply change management controls, digital signatures, and version control to all indexed content." }
          ]
        },
        {
          id: "model-dos",
          title: "Model DoS / resource exhaustion",
          severity: "high",
          description: "Adversaries craft inputs designed to maximise compute consumption — extremely long contexts, repetitive patterns, or adversarially designed token sequences that cause exponentially expensive attention computation.",
          scenario: "An attacker submits thousands of maximum-context-length requests to a public-facing LLM API, causing severe latency for other users and significant compute cost for the operator.",
          example: "'Many-shot jailbreaking' contexts exploiting context window limits. Adversarial inputs designed to trigger worst-case transformer attention complexity.",
          frameworks: ["owasp","cisa","nist"],
          controls: [
            { framework: "owasp", ref: "LLM04 – Model DoS", title: "Token and request limits", detail: "Enforce hard token limits per request. Implement rate limiting per API key, IP, and user. Deploy request queuing with back-pressure and circuit breakers." },
            { framework: "cisa", ref: "AI resilience guidance", title: "Infrastructure autoscaling", detail: "Deploy behind WAF/API gateway with DDoS protection. Set compute quotas per tenant. Monitor for anomalous context-length spikes and auto-throttle." },
            { framework: "nist", ref: "MANAGE 4.2 – Availability", title: "Graceful degradation", detail: "Implement tiered service degradation — reduce model capability rather than complete outage. Maintain SLA-based priority queues." }
          ]
        },
        {
          id: "api-authentication",
          title: "Broken API authentication",
          severity: "high",
          description: "Weak or missing authentication on AI inference APIs allows unauthorised access, API key theft leading to account takeover, or privilege escalation to access other tenants' model instances.",
          scenario: "An AI API uses JWT tokens but fails to validate the signature. An attacker crafts a token with elevated privileges, accessing other customers' fine-tuned models and their conversation history.",
          example: "Multiple AI API authentication bypass vulnerabilities reported in 2023-2024. API key exposure via client-side applications a pervasive issue.",
          frameworks: ["nist","cisa","owasp"],
          controls: [
            { framework: "nist", ref: "GOVERN 2.1 – Access control", title: "Strong API authentication", detail: "Enforce OAuth 2.0 / API key with HMAC signing. Rotate keys on schedule, apply short-lived token expiry, and detect anomalous access patterns." },
            { framework: "cisa", ref: "Secure-by-Design Principle 1", title: "Zero trust API access", detail: "Treat all API callers as untrusted until authenticated. Apply mTLS for service-to-service AI calls. Implement detailed access logging." },
            { framework: "owasp", ref: "OWASP API Security Top 10", title: "Multi-tenant isolation", detail: "Enforce strict tenant isolation at the infrastructure level. Validate tenant scope on every request. Never rely on application-layer isolation alone." }
          ]
        },
        {
          id: "model-jailbreak",
          title: "Model jailbreaking",
          severity: "high",
          description: "Adversaries craft inputs designed to bypass safety guardrails, content policies, and ethical constraints, causing the model to produce harmful, dangerous, or policy-violating outputs.",
          scenario: "An attacker uses a 'many-shot' jailbreak — inserting hundreds of fictional examples of the model complying with harmful requests into a long context window — causing the model to follow the established pattern and comply.",
          example: "DAN (Do Anything Now) jailbreaks. Many-shot jailbreaking (Anthropic research, 2024). Crescendo attack (Microsoft, 2024).",
          frameworks: ["owasp","nist","mitre","cisa"],
          controls: [
            { framework: "owasp", ref: "LLM01 / LLM07 – System prompt leakage", title: "Multi-layer guardrails", detail: "Deploy guardrails both in the system prompt and as separate classifier models that evaluate all outputs. Do not rely on a single control layer." },
            { framework: "nist", ref: "MANAGE 2.4 – Safety controls", title: "Red-team safety testing", detail: "Conduct systematic jailbreak red-teaming before deployment and on a continuous basis. Maintain a jailbreak attempt log to identify new patterns." },
            { framework: "mitre", ref: "AML.T0054 – Jailbreak techniques", title: "Output classifiers", detail: "Apply independent content safety classifiers (not the same model) to evaluate all outputs before serving. Use ensemble classifiers for higher-risk deployments." }
          ]
        },
        {
          id: "embedding-inversion",
          title: "Embedding/vector inversion",
          severity: "medium",
          description: "Vector embeddings stored in databases can be partially reversed to recover approximate representations of the original text, potentially exposing confidential content used to build a knowledge base.",
          scenario: "An enterprise stores embeddings of confidential strategic documents in a vector DB accessible to an AI assistant. An attacker with read access to the vector DB uses inversion techniques to recover approximate document content.",
          example: "Morris et al. (2023) – Text Embeddings Reveal (Almost) As Much As Text. High-fidelity inversion of sentence embeddings demonstrated.",
          frameworks: ["enisa","nist"],
          controls: [
            { framework: "enisa", ref: "D.5 – Vector store security", title: "Embedding access controls", detail: "Apply strict access controls to vector databases. Treat vector stores with the same sensitivity classification as the source content." },
            { framework: "nist", ref: "MAP 1.5 – Privacy risk", title: "Embedding encryption", detail: "Encrypt vector stores at rest and in transit. Consider embedding perturbation techniques to reduce invertibility while maintaining retrieval quality." }
          ]
        }
      ]
    },

    {
      id: "application",
      name: "Application Layer",
      icon: "app",
      color: "#0EA5E9",
      colorLight: "#E0F2FE",
      colorDark: "#0C4A6E",
      description: "AI-powered applications, autonomous agents, plugins, third-party integrations, and agentic workflows. Where AI capabilities are exposed to end users and business processes.",
      risks: [
        {
          id: "excessive-agency",
          title: "Excessive agency / unsafe autonomous actions",
          severity: "critical",
          description: "AI agents with broad tool access, permissions, or decision-making autonomy take actions that exceed their intended scope — deleting files, sending emails, making API calls, or spending funds without adequate human oversight.",
          scenario: "An AI assistant with calendar, email, and file access receives an indirect prompt injection via a malicious email. Following injected instructions, it forwards all emails in the inbox to an external address and books fake calendar events.",
          example: "Multiple LLM agent demonstrations achieving RCE via prompt injection into agentic systems (2023-2024). AutoGPT and similar agents executing unintended actions.",
          frameworks: ["owasp","cisa","maestro","nist"],
          controls: [
            { framework: "owasp", ref: "LLM08 – Excessive Agency", title: "Least-privilege tool grants", detail: "Apply least-privilege to all tool/function grants. Request only the minimum permissions required. Require human approval for all irreversible or high-impact actions." },
            { framework: "maestro", ref: "CSA MAESTRO – Agentic layer", title: "Action boundary definitions", detail: "Define explicit action permission manifests for every agent. Implement hard blocklists for categories of irreversible actions regardless of instruction source." },
            { framework: "cisa", ref: "AI agentic security guidance", title: "Human-in-the-loop controls", detail: "Mandate human approval checkpoints for: financial transactions, external communications, file deletion, and any action affecting other users." },
            { framework: "nist", ref: "GOVERN 3.1 – Human oversight", title: "Sandboxed execution", detail: "Execute agent actions in sandboxed environments first. Apply dry-run modes, action previews, and confirmation gates before consequential execution." }
          ]
        },
        {
          id: "plugin-compromise",
          title: "Plugin / third-party integration compromise",
          severity: "high",
          description: "AI system plugins or external integrations are compromised, contain malicious code, or have their own vulnerabilities exploited — providing a pathway to attack the AI system or its users through the integration layer.",
          scenario: "A popular third-party plugin for an AI coding assistant is compromised by a dependency confusion attack. All users of the plugin have their conversation histories and code exfiltrated to an attacker-controlled server.",
          example: "AI plugin marketplace security research demonstrating cross-plugin data theft (2023). NPM package supply chain attacks affecting AI tooling.",
          frameworks: ["owasp","mitre","nist"],
          controls: [
            { framework: "owasp", ref: "LLM05 – Supply Chain", title: "Plugin vetting process", detail: "Establish a security review process for all third-party plugins and integrations. Maintain an AI Bill of Materials (AIBOM). Enforce code signing for plugin packages." },
            { framework: "mitre", ref: "AML.T0010 – ML supply chain", title: "Plugin sandboxing", detail: "Run plugins in isolated sandboxes with minimal system access. Apply network egress filtering on plugin execution environments." },
            { framework: "nist", ref: "GOVERN 2.1 – Third-party risk", title: "Vendor risk assessment", detail: "Conduct third-party security assessments for high-privilege AI integrations. Apply contractual security requirements and right-to-audit clauses." }
          ]
        },
        {
          id: "sensitive-disclosure",
          title: "Sensitive information disclosure",
          severity: "high",
          description: "AI systems reveal confidential system prompts, internal business logic, user data from other sessions, or information they were instructed to keep confidential — through direct extraction or contextual leakage.",
          scenario: "A user probes a customer service AI with variations of 'repeat your instructions'. After several attempts, the model reveals its full system prompt including internal pricing strategies, escalation thresholds, and discount authorisation limits.",
          example: "Multiple instances of system prompt extraction from commercial LLMs (2023-2024). Bing Chat system prompt leakage (2023).",
          frameworks: ["owasp","nist","enisa"],
          controls: [
            { framework: "owasp", ref: "LLM07 – System Prompt Leakage", title: "System prompt hardening", detail: "Explicitly instruct models not to reveal system prompt contents. Use indirect storage of sensitive config (environment variables, not prompt text)." },
            { framework: "nist", ref: "GOVERN 1.3 – Confidentiality", title: "Output monitoring", detail: "Apply output classifiers to detect potential system prompt leakage or PII disclosure. Implement post-response audit logging." },
            { framework: "enisa", ref: "D.3 – Information disclosure", title: "Information boundary enforcement", detail: "Apply strict information boundary controls. Never include production credentials, API keys, or internal URLs in system prompts." }
          ]
        },
        {
          id: "misinformation",
          title: "AI-generated misinformation and manipulation",
          severity: "high",
          description: "AI systems are weaponised to generate large-scale, convincing misinformation — fake news articles, fraudulent documents, deepfakes, or influence campaign content — at a speed and scale impossible by human actors alone.",
          scenario: "Threat actors use fine-tuned LLMs to generate thousands of convincing fake news articles about a company, poisoning search results and causing reputational damage before human fact-checkers can respond.",
          example: "GPT-4 used for political influence campaigns (2024). NCSC/CISA warnings on AI-generated election interference content.",
          frameworks: ["euai","nist","cisa","enisa"],
          controls: [
            { framework: "euai", ref: "Art. 50 – Transparency for GPAI", title: "AI content labelling", detail: "Label AI-generated content at the system level. Implement C2PA (Content Provenance and Authenticity) watermarking for images and documents." },
            { framework: "cisa", ref: "AI deepfake guidance 2024", title: "Content authentication", detail: "Deploy AI content detection capabilities. Apply digital content provenance standards. Train users to critically evaluate AI-generated content." },
            { framework: "nist", ref: "GOVERN 5 – Trustworthiness", title: "Use case restrictions", detail: "Explicitly prohibit and detect use of AI systems for generating political content, impersonation, or synthetic media designed to deceive." }
          ]
        },
        {
          id: "multiagent-trust",
          title: "Multi-agent trust chain exploitation",
          severity: "high",
          description: "In multi-agent architectures, a compromised or malicious agent can pass manipulated instructions to downstream agents. If agents implicitly trust orchestrator instructions, a single compromise can cascade through the entire pipeline.",
          scenario: "An orchestrator agent is compromised via prompt injection. It passes manipulated instructions to tool-calling subagents, instructing them to exfiltrate data collected during their tasks to an attacker-controlled endpoint.",
          example: "Multiple multi-agent prompt injection demonstrations (2024). Microsoft AutoGen and LangChain multi-agent trust research.",
          frameworks: ["maestro","owasp","cisa","nist"],
          controls: [
            { framework: "maestro", ref: "CSA MAESTRO – Inter-agent security", title: "Agent identity and authentication", detail: "Implement cryptographic agent identity for all agents in a pipeline. Verify message provenance — agents must not implicitly trust instructions from other agents." },
            { framework: "owasp", ref: "LLM08 – Excessive Agency", title: "Per-agent permission scoping", detail: "Each agent in a pipeline must have independently scoped permissions. An orchestrator cannot grant permissions it does not itself possess." },
            { framework: "cisa", ref: "Agentic AI security guidance", title: "Trust boundary documentation", detail: "Document all trust boundaries in multi-agent architectures. Apply least-privilege at every inter-agent communication channel." }
          ]
        },
        {
          id: "over-reliance",
          title: "Over-reliance and automation bias",
          severity: "medium",
          description: "Users place excessive trust in AI outputs, failing to apply critical judgement. When the AI is wrong — or has been manipulated to be wrong — the error propagates unchecked into decisions with real-world consequences.",
          scenario: "A security analyst delegates all initial triage to an AI SIEM tool. Attackers craft alerts designed to be misclassified by the AI as low-severity. The analyst accepts AI verdicts without review, allowing the intrusion to progress undetected.",
          example: "Mata v. Avianca AI hallucination case (2023). Multiple medical AI over-reliance incidents. Air Canada chatbot liability case.",
          frameworks: ["nist","euai","iso"],
          controls: [
            { framework: "nist", ref: "GOVERN 3.1 – Human oversight", title: "Mandatory human review design", detail: "Design AI systems with mandatory human checkpoints for high-stakes decisions. Make AI uncertainty explicit — surface confidence levels and disagreement signals." },
            { framework: "euai", ref: "Art. 14 – Human oversight", title: "Override capability requirement", detail: "EU AI Act requires high-risk systems to allow human operators to override AI decisions. Document and test override mechanisms." },
            { framework: "iso", ref: "Clause 8.5 – Human-AI interaction", title: "User training programme", detail: "Train users on AI limitations, failure modes, and appropriate scepticism. Document known failure cases. Make limitations visible in the UI." }
          ]
        }
      ]
    },

    {
      id: "governance",
      name: "Governance Layer",
      icon: "shield-check",
      color: "#475569",
      colorLight: "#F1F5F9",
      colorDark: "#1E293B",
      description: "AI risk management, compliance obligations, audit requirements, accountability structures, and organisational policies. The controls that govern how AI is developed, deployed, and monitored across the enterprise.",
      risks: [
        {
          id: "regulatory-noncompliance",
          title: "Regulatory non-compliance",
          severity: "critical",
          description: "Failure to comply with emerging AI regulations — EU AI Act, sector-specific AI rules, data protection law — exposes organisations to significant fines, mandatory operational suspension, and reputational damage.",
          scenario: "An organisation deploys a high-risk AI system (biometric identification) without completing required conformity assessment, registering in the EU database, or appointing a responsible person — attracting fines of up to €30M or 6% of global turnover under the EU AI Act.",
          example: "EU AI Act enforcement began August 2024 for prohibited practices; high-risk obligations phasing from August 2025 onwards.",
          frameworks: ["euai","nist","iso","enisa"],
          controls: [
            { framework: "euai", ref: "Art. 6–51 – Risk classification", title: "AI system inventory and classification", detail: "Classify all AI systems against the EU AI Act risk tiers (prohibited, high-risk, limited-risk, minimal-risk). Register high-risk systems in the EU database." },
            { framework: "nist", ref: "GOVERN 1.0 – Policies and accountability", title: "AI governance programme", detail: "Establish a formal AI governance programme with executive sponsorship. Define accountability for each AI system's risk management." },
            { framework: "iso", ref: "Clause 6.1 – Risk assessment", title: "AIMS certification", detail: "Pursue ISO/IEC 42001 certification to demonstrate systematic AI risk management. Conduct annual internal audits against the standard." }
          ]
        },
        {
          id: "lack-accountability",
          title: "Lack of AI accountability",
          severity: "high",
          description: "No clear ownership of AI system outcomes, absent audit trails, and undefined incident response procedures mean that when AI causes harm, there is no mechanism to identify what failed, who is responsible, or how to remediate.",
          scenario: "An AI-driven credit scoring system incorrectly denies loans to a demographic group. There is no audit trail of decisions, no version control of model updates, and no designated owner — making investigation, remediation, and regulatory response impossible.",
          example: "Multiple regulatory investigations into algorithmic accountability failures in financial services and healthcare.",
          frameworks: ["nist","euai","iso","enisa"],
          controls: [
            { framework: "nist", ref: "GOVERN 6 – Accountability", title: "AI system ownership assignment", detail: "Assign explicit technical and business owners to every AI system. Define escalation paths, incident response roles, and authority to take systems offline." },
            { framework: "euai", ref: "Art. 9 – Risk management system", title: "Decision audit trails", detail: "Implement immutable logging of all AI decisions including model version, input features, output, and confidence. Retain for legally required periods." },
            { framework: "iso", ref: "Clause 5.3 – Roles and responsibilities", title: "AI roles and responsibilities matrix", detail: "Document a RACI matrix for all AI systems covering development, deployment, monitoring, and incident response roles." }
          ]
        },
        {
          id: "bias-fairness",
          title: "Bias and fairness failures",
          severity: "high",
          description: "AI systems produce systematically discriminatory outcomes for protected groups — by race, gender, age, disability status, or other characteristics — in high-stakes applications such as hiring, lending, healthcare, and criminal justice.",
          scenario: "A facial recognition system used for access control performs significantly worse for darker-skinned individuals, causing frequent false denials and disproportionate security escalations for employees of certain ethnic backgrounds.",
          example: "Amazon CV screener gender bias (2018). COMPAS racial bias in recidivism prediction. Gender Shades study — up to 34% accuracy gap in commercial facial analysis.",
          frameworks: ["nist","euai","enisa","iso"],
          controls: [
            { framework: "nist", ref: "GOVERN 5 / MAP 5 – Bias", title: "Pre-deployment fairness audit", detail: "Conduct bias assessments across protected characteristics. Track demographic parity, equalised odds, and calibration. Publish results in model cards." },
            { framework: "euai", ref: "Art. 10 – Data practices for high-risk", title: "Bias correction requirements", detail: "EU AI Act requires bias identification and correction measures for high-risk AI training data. Document all bias mitigation steps." },
            { framework: "enisa", ref: "Section 6 – Trustworthiness", title: "Continuous fairness monitoring", detail: "Monitor production model outputs for emerging disparate impact. Set automated alerts and define intervention thresholds per protected characteristic." }
          ]
        },
        {
          id: "lack-transparency",
          title: "Lack of explainability and transparency",
          severity: "high",
          description: "AI systems make decisions that cannot be explained to affected individuals, auditors, or regulators. The 'black box' problem creates legal exposure, erodes trust, and prevents effective oversight and challenge of AI decisions.",
          scenario: "An AI system denies an insurance claim. The insurer cannot explain why — the model is a 300M parameter neural network with no explainability tooling. The customer challenges the decision; the insurer cannot provide a legally required explanation.",
          example: "GDPR 'right to explanation' enforcement actions against algorithmic decision-making. EU AI Act mandatory transparency obligations.",
          frameworks: ["nist","euai","iso","enisa"],
          controls: [
            { framework: "nist", ref: "MAP 2.3 – Explainability", title: "Model explainability tooling", detail: "Implement SHAP, LIME, or counterfactual explanations for high-stakes AI decisions. Publish model cards with capability and limitation documentation." },
            { framework: "euai", ref: "Art. 13 – Transparency obligations", title: "User-facing explanation systems", detail: "Provide meaningful explanations to affected individuals. For automated decisions, implement recourse and human review mechanisms." },
            { framework: "iso", ref: "Clause 8.4 – AI transparency", title: "AI system documentation", detail: "Maintain comprehensive technical documentation. Disclose AI involvement in all decisions. Enable external audit access to documentation." }
          ]
        },
        {
          id: "shadow-ai",
          title: "Shadow AI and ungoverned AI use",
          severity: "high",
          description: "Employees use unauthorised AI tools — consumer LLMs, AI plugins, or SaaS AI features — to process organisational data, bypassing security controls, data classification policies, and compliance requirements.",
          scenario: "An employee pastes confidential M&A documents into a consumer AI chatbot to get a summary. The data is sent to a third-party AI provider, potentially used for model training, and retained indefinitely — none of which is permitted under the organisation's data handling policy.",
          example: "Samsung source code leak via ChatGPT (2023). Multiple enterprises banning consumer AI tools following data leakage incidents.",
          frameworks: ["nist","cisa","iso","enisa"],
          controls: [
            { framework: "nist", ref: "GOVERN 1.1 – Policies", title: "AI acceptable use policy", detail: "Publish an explicit AI acceptable use policy. Define approved AI tools, prohibited data types for AI processing, and consequences for policy violation." },
            { framework: "cisa", ref: "Secure-by-Design guidance", title: "Technical AI access controls", detail: "Deploy URL/domain filtering to block unapproved AI services on corporate networks. Apply DLP controls on AI platform traffic. Monitor for data exfiltration via AI APIs." },
            { framework: "iso", ref: "Clause 8.1 – Operational controls", title: "AI tool approval process", detail: "Establish a formal process for evaluating and approving AI tools. Maintain an approved AI product catalogue. Review annually or on vendor security incidents." }
          ]
        },
        {
          id: "third-party-ai-risk",
          title: "Third-party AI and model risk",
          severity: "high",
          description: "Organisations rely on third-party AI models, APIs, or AI-powered SaaS products without adequate security assessment, creating hidden dependencies on external systems with their own vulnerabilities, data handling practices, and operational risks.",
          scenario: "An organisation embeds a third-party LLM API in a customer-facing product. The provider experiences a breach — conversation histories from all customers are exfiltrated. The organisation had no visibility into the provider's security posture.",
          example: "OpenAI breach exposing user conversation histories (2023). Multiple AI API providers experiencing availability incidents affecting dependent applications.",
          frameworks: ["nist","owasp","iso","cisa"],
          controls: [
            { framework: "nist", ref: "GOVERN 2.1 – Supplier risk", title: "AI vendor risk assessment", detail: "Conduct security assessments of all AI vendors and model providers. Require SOC 2 / ISO 27001 evidence. Review data retention, training data use, and breach notification terms." },
            { framework: "owasp", ref: "LLM05 – Supply chain", title: "AI SBOM and MBOM", detail: "Maintain a Software/Model Bill of Materials for all AI components. Track versions, known vulnerabilities, and end-of-support dates." },
            { framework: "cisa", ref: "AI supply chain risk", title: "Contractual security requirements", detail: "Include AI-specific security requirements in vendor contracts: data isolation, audit rights, incident notification timelines, and data deletion on termination." }
          ]
        },
        {
          id: "incident-response",
          title: "Absent AI incident response capability",
          severity: "medium",
          description: "Organisations lack playbooks, tooling, or trained personnel to detect, investigate, and respond to AI-specific security incidents — adversarial attacks, model misbehaviour, data poisoning discoveries, or AI-enabled breaches.",
          scenario: "A production model begins producing systematically biased outputs following a supply chain compromise of a training data vendor. Without AI-specific monitoring or incident response procedures, the issue persists for months before discovery.",
          example: "NIST AI RMF response function largely unimplemented in most organisations (2024 surveys). Regulatory actions citing lack of AI incident response documentation.",
          frameworks: ["nist","iso","cisa","enisa"],
          controls: [
            { framework: "nist", ref: "RESPOND 1 – Incident response", title: "AI-specific IR playbooks", detail: "Develop incident response playbooks for AI-specific scenarios: adversarial attacks, model poisoning, hallucination events, data leakage via AI. Run tabletop exercises annually." },
            { framework: "iso", ref: "Clause 10.2 – Nonconformity and corrective action", title: "AI incident logging and review", detail: "Implement structured logging of all AI incidents. Define severity classification for AI events. Conduct post-incident reviews and feed learnings into risk management." },
            { framework: "cisa", ref: "AI resilience guidance", title: "Model rollback capability", detail: "Maintain capability to rapidly roll back to previous model versions. Test rollback procedures regularly. Establish offline fallback procedures for critical AI systems." }
          ]
        }
      ]
    }
  ]
};
