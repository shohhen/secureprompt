"use client";

import { useState } from "react";

type Status = "idle" | "loading" | "success" | "error";

export function ContactForm({ onClose }: { onClose?: () => void }) {
  const [formData, setFormData] = useState({ name: "", email: "", message: "" });
  const [status, setStatus] = useState<Status>("idle");
  const [errorMessage, setErrorMessage] = useState("");

  const handleChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>,
  ) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setStatus("loading");
    setErrorMessage("");

    try {
      const response = await fetch("/api/contact", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formData),
      });

      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.error || `Request failed (${response.status})`);
      }

      setStatus("success");
      setFormData({ name: "", email: "", message: "" });
      if (onClose) setTimeout(onClose, 1800);
    } catch (error) {
      setStatus("error");
      setErrorMessage(
        error instanceof Error ? error.message : "An error occurred",
      );
    }
  };

  return (
    <form onSubmit={handleSubmit} className="contact-form">
      <h3>get in touch</h3>
      <p className="contact-sub">
        tell us about your stack. we&apos;ll reply within one business day.
      </p>

      {status === "success" && (
        <div className="form-message success">
          ✓ thanks — your message is in. we&apos;ll be in touch.
        </div>
      )}
      {status === "error" && (
        <div className="form-message error">
          ✗ {errorMessage || "couldn't send. try again or email directly."}
        </div>
      )}

      <div className="form-group">
        <label htmlFor="name">name</label>
        <input
          id="name"
          type="text"
          name="name"
          placeholder="your name"
          value={formData.name}
          onChange={handleChange}
          required
          disabled={status === "loading"}
        />
      </div>

      <div className="form-group">
        <label htmlFor="email">email</label>
        <input
          id="email"
          type="email"
          name="email"
          placeholder="you@company.com"
          value={formData.email}
          onChange={handleChange}
          required
          disabled={status === "loading"}
        />
      </div>

      <div className="form-group">
        <label htmlFor="message">message</label>
        <textarea
          id="message"
          name="message"
          placeholder="what are you building? what's the deployment shape?"
          rows={4}
          value={formData.message}
          onChange={handleChange}
          required
          disabled={status === "loading"}
        />
      </div>

      <button
        type="submit"
        disabled={status === "loading"}
        className={`submit-btn ${status === "loading" ? "loading" : ""}`}
      >
        {status === "loading" ? "sending..." : "send message →"}
      </button>
    </form>
  );
}
