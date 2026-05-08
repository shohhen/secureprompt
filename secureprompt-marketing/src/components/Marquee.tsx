const items: { text: string; accent: boolean }[] = [
  { text: "// AI security gateway", accent: true },
  { text: "on-prem only", accent: false },
  { text: "// openai · anthropic · google · azure · vllm · ollama", accent: true },
  { text: "air-gap capable", accent: false },
  { text: "// PII redaction", accent: true },
  { text: "prompt-injection blocking", accent: false },
  { text: "// per-request audit log", accent: true },
  { text: "tokenized streaming", accent: false },
];

export function Marquee() {
  // Duplicate the list so the CSS translate(-50%) loops seamlessly
  const stream = [...items, ...items];
  return (
    <div className="marquee">
      <div className="marquee-track">
        {stream.map((it, i) => (
          <span key={i} className={it.accent ? "acc" : undefined}>
            {it.text}
          </span>
        ))}
      </div>
    </div>
  );
}
