const cells: { letter: string; title: string; body: string }[] = [
  {
    letter: "A",
    title: "security & compliance",
    body: "Teams who need to say yes to AI without inheriting third-party data risk.",
  },
  {
    letter: "B",
    title: "platform engineering",
    body: 'Companies that have outgrown "every team picks their own LLM API key."',
  },
  {
    letter: "C",
    title: "regulated industries",
    body: "Healthcare, finance, legal, government — where data sovereignty isn't optional.",
  },
  {
    letter: "D",
    title: "on-prem mandates",
    body: "IP-sensitive engineering, model evaluation, sovereign deployments.",
  },
  {
    letter: "E",
    title: "self-hosted models",
    body: "Teams running vLLM or Ollama who want one policy and audit layer across self-hosted and commercial.",
  },
];

export function Audience() {
  return (
    <section className="section" id="audience">
      <div className="section-head">
        <div className="section-num">
          [ 05 ]<span className="lbl">built for</span>
        </div>
        <div>
          <div className="section-eyebrow-line">
            // if you have more than a handful of LLM integrations
          </div>
          <h2 className="editorial">
            <span className="row">
              <span className="word">you</span>{" "}
              <span className="word delay-1">have</span>{" "}
              <span className="word delay-2">this</span>{" "}
              <span className="word delay-3 accent">problem.</span>
            </span>
          </h2>
        </div>
      </div>

      <div className="agrid">
        {cells.map((c) => (
          <div className="acell" key={c.letter}>
            <span className="ai">[ {c.letter} ]</span>
            <h4>{c.title}</h4>
            <p>{c.body}</p>
          </div>
        ))}
      </div>
    </section>
  );
}
