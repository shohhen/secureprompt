"use client";

import { useState, type ReactNode } from "react";

export interface Point {
  title: string;
  body: string;
}

export function NumRow({
  idx,
  defaultOpen = false,
  heading,
  points,
  extra,
}: {
  idx: string;
  defaultOpen?: boolean;
  heading: ReactNode;
  points: Point[];
  extra?: ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className={`nrow${open ? " open" : ""}`} onClick={() => setOpen((o) => !o)}>
      <div className="nidx">{idx}</div>
      <div className="nbody">
        <h3>{heading}</h3>
        <div className="points">
          {points.map((p, i) => (
            <div className="pt" key={i}>
              <span className="slash">//</span>
              <div>
                <strong>{p.title}</strong>
                {p.body}
              </div>
            </div>
          ))}
          {extra}
        </div>
      </div>
      <div className="ntoggle">+</div>
    </div>
  );
}
