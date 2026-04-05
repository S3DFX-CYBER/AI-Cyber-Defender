const STYLES = `
:root {
  --bg: #0e0e10;
  --surface: #19191d;
  --surface-2: #25252b;
  --surface-3: #1f1f24;
  --text: #e7e4ec;
  --text-muted: #acaab1;
  --primary: #c6c6c9;
  --primary-dark: #454749;
  --tertiary: #b68fff;
  --outline: #47474e;
}
* { box-sizing: border-box; }
html, body, #root { margin: 0; min-height: 100%; }
body {
  font-family: 'Manrope', system-ui, -apple-system, sans-serif;
  background: var(--bg);
  color: var(--text);
}
.page { position: relative; overflow-x: hidden; }
.serif { font-family: 'Newsreader', Georgia, serif; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.container { max-width: 1440px; margin: 0 auto; padding: 0 48px; }
.glow {
  position: fixed;
  width: 560px;
  height: 560px;
  border-radius: 999px;
  filter: blur(150px);
  background: rgba(182, 143, 255, 0.11);
  pointer-events: none;
  z-index: -1;
}
.glow.one { top: -90px; left: 12%; }
.glow.two { right: 12%; bottom: -120px; }

.nav {
  position: fixed;
  top: 0;
  width: 100%;
  z-index: 100;
  backdrop-filter: blur(18px);
  background: rgba(14, 14, 16, 0.7);
  border-bottom: 1px solid rgba(71, 71, 78, 0.35);
}
.nav-inner {
  min-height: 86px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}
.brand { font-size: 1.65rem; font-style: italic; letter-spacing: -0.02em; }
.nav-links { display: flex; gap: 36px; }
.nav-links a {
  color: #9f9ea6;
  text-decoration: none;
  font-family: 'Newsreader', serif;
  font-size: 1.2rem;
}
.nav-links a.active, .nav-links a:hover { color: #f1f0f6; }
.nav-links a.active { border-bottom: 1px solid #6f6e77; padding-bottom: 4px; }

.btn {
  border: none;
  border-radius: 8px;
  padding: 12px 22px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  font-size: 0.72rem;
  cursor: pointer;
}
.btn-primary {
  background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
  color: #17181b;
}
.btn-secondary {
  background: var(--surface-2);
  color: var(--text);
  border: 1px solid rgba(117, 117, 124, 0.3);
}

main { padding-top: 140px; }
.hero {
  display: grid;
  grid-template-columns: 1.7fr 1fr;
  align-items: end;
  gap: 42px;
  padding-bottom: 120px;
}
.hero h1 {
  margin: 0;
  font-size: clamp(3rem, 8vw, 7rem);
  line-height: 1.04;
  font-style: italic;
  letter-spacing: -0.03em;
}
.hero h1 span { color: #b8b8bb; font-style: normal; }
.hero p { color: var(--text-muted); font-size: 1.22rem; line-height: 1.75; max-width: 480px; }
.hero-actions { display: flex; gap: 12px; margin-top: 24px; }

.image-break { margin-bottom: 130px; }
.image-wrap {
  height: 560px;
  border-radius: 14px;
  overflow: hidden;
  position: relative;
  filter: grayscale(100%);
  transition: 0.7s ease;
}
.image-wrap:hover { filter: grayscale(0%); }
.image-wrap img { width: 100%; height: 100%; object-fit: cover; }
.image-wrap::after {
  content: '';
  position: absolute;
  inset: 0;
  background: linear-gradient(180deg, transparent, rgba(14,14,16,0.6));
}

.section { margin-bottom: 150px; }
.section-header h2 {
  font-size: clamp(2rem, 5vw, 3.8rem);
  margin: 0 0 14px;
  line-height: 1.1;
}
.section-header p { color: var(--text-muted); max-width: 560px; }

.problem {
  display: grid;
  grid-template-columns: 1fr 1.5fr;
  gap: 56px;
}
.mini-label {
  color: #b188ff;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  font-size: 0.72rem;
  font-weight: 800;
}
.cards-2x2 {
  display: grid;
  grid-template-columns: repeat(2, minmax(220px, 1fr));
  gap: 26px 34px;
}
.info-card h3 { margin: 0 0 8px; font-size: 1.65rem; }
.info-card p { margin: 0; color: var(--text-muted); line-height: 1.7; }

.pipeline {
  background: var(--surface);
  padding: 110px 0;
}
.pipeline-cards {
  margin-top: 48px;
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 1px;
  background: rgba(117,117,124,0.2);
  border-radius: 14px;
  overflow: hidden;
}
.pipeline-card {
  background: var(--bg);
  padding: 40px;
}
.pipeline-card h4 { margin: 0 0 10px; font-size: 1.8rem; }
.pipeline-card p { color: var(--text-muted); line-height: 1.7; }

.arch-shell {
  background: #131316;
  border-radius: 16px;
  padding: 56px;
}
.arch-grid { display: grid; grid-template-columns: 1fr 1.2fr; gap: 50px; align-items: center; }
.arch-flow { display: grid; grid-template-columns: 1fr auto 1fr auto 1fr; gap: 10px; align-items: center; }
.node {
  background: var(--surface-3);
  border: 1px solid rgba(117,117,124,0.25);
  border-radius: 10px;
  padding: 24px;
  text-align: center;
}
.node.center { background: #2f3235; border-color: rgba(198,198,201,0.24); }
.arrow { color: #75757c; font-size: 1.4rem; }

.dashboard {
  display: grid;
  grid-template-columns: 1.3fr 1fr;
  gap: 40px;
  align-items: center;
}
.dashboard img {
  width: 100%;
  height: 390px;
  object-fit: cover;
  border-radius: 12px;
  opacity: 0.85;
}
.window {
  padding: 16px;
  border: 1px solid rgba(117,117,124,0.25);
  background: var(--surface-2);
  border-radius: 14px;
}

.codebox {
  max-width: 850px;
  margin: 0 auto;
  background: #000;
  border-radius: 14px;
  border: 1px solid rgba(117,117,124,0.2);
  overflow: hidden;
}
.codebox-head {
  padding: 12px 18px;
  background: #25252b;
  border-bottom: 1px solid rgba(117,117,124,0.2);
  display: flex;
  justify-content: space-between;
}
pre { margin: 0; padding: 26px; color: #d4d4d7; overflow-x: auto; font-size: 0.95rem; line-height: 1.8; }

.footer {
  border-top: 1px solid rgba(39,39,42,0.8);
  background: #09090b;
  padding: 50px 0;
}
.footer-inner { display: flex; justify-content: space-between; gap: 20px; flex-wrap: wrap; align-items: center; }
.footer-links { display: flex; gap: 24px; }
.footer-links a { color: #a1a1aa; text-decoration: none; font-size: 0.95rem; }
.footer-links a:hover { color: #c4b5fd; }

@media (max-width: 1100px) {
  .hero, .problem, .arch-grid, .dashboard { grid-template-columns: 1fr; }
  .pipeline-cards { grid-template-columns: 1fr; }
}
@media (max-width: 780px) {
  .container { padding: 0 20px; }
  .nav-links { display: none; }
  .hero-actions { flex-wrap: wrap; }
  .cards-2x2 { grid-template-columns: 1fr; }
  .arch-flow { grid-template-columns: 1fr; }
  .arrow { transform: rotate(90deg); text-align: center; }
}
`;

function App() {
  return (
    <>
      <style>{STYLES}</style>
      <link rel="preconnect" href="https://fonts.googleapis.com" />
      <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="" />
      <link href="https://fonts.googleapis.com/css2?family=Newsreader:ital,wght@0,300..800;1,300..800&family=Manrope:wght@200..800&display=swap" rel="stylesheet" />

      <div className="page">
        <div className="glow one" />
        <div className="glow two" />

        <nav className="nav">
          <div className="container nav-inner">
            <div className="brand serif">TENET AI</div>
            <div className="nav-links">
              <a href="#" className="active">Platform</a>
              <a href="#">Intelligence</a>
              <a href="#">Documentation</a>
            </div>
            <button className="btn btn-primary">Secure Access</button>
          </div>
        </nav>

        <main>
          <section className="container hero">
            <h1 className="serif">The Defensive Middleware for <span>LLM Applications.</span></h1>
            <div>
              <p>
                Hardening generative intelligence against adversarial intent. Tenet AI sits between your users and your model, sanitizing every interaction in real-time.
              </p>
              <div className="hero-actions">
                <button className="btn btn-primary">Deploy Shield</button>
                <button className="btn btn-secondary">Read Paper</button>
              </div>
            </div>
          </section>

          <section className="container image-break">
            <div className="image-wrap">
              <img alt="Abstract digital obsidian sculpture with soft violet reflections" src="https://lh3.googleusercontent.com/aida-public/AB6AXuCjbkhfw-kH7VdcAeaU4W7Ymn1Tkgirmss0EkVQmaJppQ5x7TYxRofQE3J8cgJhdsLfdJbLFxGS7oTrFGpy1adSvAMY-mgoukvYc1uBL83xTw2wI5urzTNCvLhpofmpLEoeYxmuNTB7N6NM0vGqykVGY32dGyAKAWIgi6DWHGg0xfDPeqZZG-ufJJl1588LgmKnbvXFslj2gkXrmTi01WaiGRJtuDnUOQm-TnOtX2CEKhsbmFURkCTfPWn81dSakBIr6bojK39AG_kg" />
            </div>
          </section>

          <section className="container section problem">
            <div>
              <div className="mini-label">Fragile Intelligence</div>
              <h2 className="serif">Modern attack vectors are evolving faster than models can be patched.</h2>
            </div>
            <div className="cards-2x2">
              {[
                ["Prompt Injection", "Adversarial instructions designed to bypass system prompts and execute malicious logic."],
                ["Jailbreaking", "Sophisticated linguistic maneuvering to force LLMs into producing restricted content."],
                ["Data Extraction", "Indirect queries aimed at leaking sensitive training data or proprietary instructions."],
                ["PII Leakage", "Accidental transmission of personal information through unstructured natural-language prompts."],
              ].map(([title, text]) => (
                <article className="info-card" key={title}>
                  <h3 className="serif">{title}</h3>
                  <p>{text}</p>
                </article>
              ))}
            </div>
          </section>

          <section className="pipeline section">
            <div className="container">
              <div className="section-header">
                <h2 className="serif">A Multi-Layered Security Pipeline.</h2>
                <p>Tenet processes every token through three analytical tiers before it reaches core application logic.</p>
              </div>
              <div className="pipeline-cards">
                <article className="pipeline-card">
                  <h4 className="serif">Heuristic Engine</h4>
                  <p>Pattern-based filtering for malicious strings, PII regex checks, and blocked keyword orchestration.</p>
                </article>
                <article className="pipeline-card">
                  <h4 className="serif">ML-Based Scrutiny</h4>
                  <p>BERT-derived models trained on adversarial datasets to detect semantic intent mismatch.</p>
                </article>
                <article className="pipeline-card">
                  <h4 className="serif">Behavioral Profiling</h4>
                  <p>Session-level anomaly tracking to identify rapid adversarial probing and automation patterns.</p>
                </article>
              </div>
            </div>
          </section>

          <section className="container section">
            <div className="arch-shell">
              <div className="arch-grid">
                <div>
                  <h2 className="serif">Architecture of Trust.</h2>
                  <p style={{ color: 'var(--text-muted)', lineHeight: 1.7 }}>
                    Tenet AI is an invisible security layer requiring zero provider changes—just route traffic through middleware.
                  </p>
                  <ul>
                    <li>Latency impact under 12ms</li>
                    <li>Supports OpenAI, Anthropic, and Llama</li>
                    <li>Self-hosted or cloud-native deployment</li>
                  </ul>
                </div>
                <div className="arch-flow">
                  <div className="node"><small>ORIGIN</small><p className="serif">Your App</p></div>
                  <div className="arrow">→</div>
                  <div className="node center"><small>SECURE LAYER</small><p className="serif">TENET AI</p></div>
                  <div className="arrow">→</div>
                  <div className="node"><small>DESTINATION</small><p className="serif">LLM API</p></div>
                </div>
              </div>
            </div>
          </section>

          <section className="container section dashboard">
            <div className="window">
              <img alt="SOC dashboard interface with dark charts and activity feed" src="https://lh3.googleusercontent.com/aida-public/AB6AXuBG7GOyM1YS-H0h0QJDuxQIgnUBy9v21a0fdS1oAn7raqFR8ZH39MLFLCRm2tNFhqAgZ5Yocj-YkkzBffImdeOKJkRK_MP7_7xpk3yQOyKzCAES89b5Ucq-xrqGwfOzZGihuWAIyQaMc4ebkzvfS5-bhiS-_WIMXXQbwGBTMnYFWJiOFYBH04tGW3My8IPOtq23qNawygplEjduJVpCWjCZL1n-rYxNgfL_qtgjVXQxCYMb_mTvE4oB7tqJZ29r-fbAcZ8rU3dHHjZ5" />
            </div>
            <div>
              <div className="mini-label">Coming in v0.2</div>
              <h2 className="serif">The SOC for Generative AI.</h2>
              <p style={{ color: 'var(--text-muted)', lineHeight: 1.8 }}>
                Real-time threat feeds, behavioral analytics, and automated intervention controls to visualize adversarial attempts instantly.
              </p>
            </div>
          </section>

          <section className="container section" style={{ textAlign: 'center' }}>
            <div className="section-header" style={{ textAlign: 'center' }}>
              <h2 className="serif">Integrated in Minutes.</h2>
              <p style={{ margin: '0 auto' }}>One plugin. Three lines of code. Enterprise-grade security for your model pipeline.</p>
            </div>
            <div className="codebox">
              <div className="codebox-head">
                <span className="mono" style={{ color: '#acaab1', fontSize: '0.8rem' }}>secure_middleware.py</span>
                <span className="mini-label" style={{ margin: 0 }}>Copy Code</span>
              </div>
              <pre>{`from tenet_ai import TenetShield

# Initialize defensive layer
shield = TenetShield(api_key="tn_live_...")

# Wrap your prompt execution
with shield.protect(prompt) as safe_prompt:
    response = llm.generate(safe_prompt)
    shield.audit(response)`}</pre>
            </div>
          </section>
        </main>

        <footer className="footer">
          <div className="container footer-inner">
            <div>
              <div className="serif" style={{ fontStyle: 'italic', fontSize: '1.25rem' }}>TENET AI</div>
              <div style={{ color: '#71717a', marginTop: 6 }}>Architectural Security for the Obsidian Age.</div>
            </div>
            <div className="footer-links">
              <a href="#">Privacy</a>
              <a href="#">Terms</a>
              <a href="#">Security Ops</a>
              <a href="#">Status</a>
            </div>
            <div style={{ color: '#71717a', fontSize: '0.8rem' }}>© 2024 TENET AI. All Rights Reserved.</div>
          </div>
        </footer>
      </div>
    </>
  );
}

export default App;
