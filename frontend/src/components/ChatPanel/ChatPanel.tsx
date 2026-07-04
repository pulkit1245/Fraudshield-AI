// Chat-with-the-APK panel: POST /submissions/{id}/chat, conversational history,
// loading state and graceful 429 rate-limit messaging. Owner: Member D.
import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { ApiRequestError } from "../../services/api";
import { submissionsApi } from "../../services/submissions";
import type { ChatMessage } from "../../types";

export default function ChatPanel({ submissionId }: { submissionId: string }) {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [notice, setNotice] = useState<string | null>(null);

  const chat = useMutation({
    mutationFn: (message: string) => submissionsApi.chat(submissionId, message),
    onSuccess: (res) => {
      setMessages((m) => [...m, { role: "assistant", text: res.reply, sources: res.sources }]);
      setNotice(res.cached ? "cached answer" : null);
    },
    onError: (err) => {
      if (err instanceof ApiRequestError && err.status === 429) {
        setNotice("Rate limit reached (Claude tier cap). Please wait a moment.");
      } else {
        setNotice("Chat is unavailable right now.");
      }
    },
  });

  function send(e: React.FormEvent) {
    e.preventDefault();
    const text = input.trim();
    if (!text || chat.isPending) return;
    setMessages((m) => [...m, { role: "user", text }]);
    setInput("");
    setNotice(null);
    chat.mutate(text);
  }

  return (
    <div className="flex h-96 flex-col rounded-xl border border-gray-200 bg-white">
      <div className="border-b border-gray-100 px-4 py-2 text-sm font-semibold text-gray-700">
        Chat with the APK
      </div>

      <div className="flex-1 space-y-3 overflow-y-auto px-4 py-3">
        {messages.length === 0 && (
          <p className="text-sm text-gray-400">
            Ask about this sample — answers are grounded in sanitized findings only.
          </p>
        )}
        {messages.map((m, i) => (
          <div key={i} className={m.role === "user" ? "text-right" : "text-left"}>
            <div
              className={`inline-block max-w-[85%] rounded-lg px-3 py-2 text-sm ${
                m.role === "user" ? "bg-indigo-600 text-white" : "bg-gray-100 text-gray-800"
              }`}
            >
              {m.text}
            </div>
            {m.sources && m.sources.length > 0 && (
              <div className="mt-1 text-[11px] text-gray-400">
                sources: {m.sources.map((s) => s.name ?? s.type).join(", ")}
              </div>
            )}
          </div>
        ))}
        {chat.isPending && <div className="text-sm text-gray-400">Thinking…</div>}
      </div>

      {notice && (
        <div className="px-4 py-1 text-xs text-amber-700">{notice}</div>
      )}

      <form onSubmit={send} className="flex gap-2 border-t border-gray-100 p-3">
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Does this app intercept OTPs?"
          aria-label="Chat message"
          className="flex-1 rounded-md border border-gray-300 px-3 py-2 text-sm"
        />
        <button
          type="submit"
          disabled={chat.isPending}
          className="rounded-md bg-indigo-600 px-3 py-2 text-sm font-semibold text-white hover:bg-indigo-700 disabled:opacity-50"
        >
          Send
        </button>
      </form>
    </div>
  );
}
