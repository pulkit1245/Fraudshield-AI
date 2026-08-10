// APK Security Assistant chat panel.
// Suggested questions, evidence-grounded answers, structured rendering,
// all loading/error/empty/partial states. Owner: Member D.
import { useEffect, useRef, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { ApiRequestError } from "../../services/api";
import { submissionsApi } from "../../services/submissions";
import type { ChatMessage, ChatSource } from "../../types";

const SUGGESTED_QUESTIONS = [
  "Why is this APK considered risky?",
  "What suspicious behaviour was detected?",
  "What happened during dynamic analysis?",
  "Which permissions are most concerning?",
  "Was any C2 network behaviour detected?",
  "What are the top MITRE ATT&CK techniques?",
  "Why did the ML model score it this way?",
  "What should I investigate next?",
];

// ── Icons (inline SVG, no library dependency) ────────────────────────────
function UserIcon() {
  return (
    <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-indigo-600 text-white text-xs font-bold">
      U
    </span>
  );
}

function AssistantIcon() {
  return (
    <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-gray-700 text-white text-xs">
      🛡
    </span>
  );
}

function SendIcon() {
  return (
    <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
    </svg>
  );
}

// ── Typing indicator ─────────────────────────────────────────────────────
function TypingIndicator() {
  return (
    <div className="flex items-end gap-2">
      <AssistantIcon />
      <div className="rounded-2xl rounded-bl-sm bg-gray-100 px-4 py-3">
        <div className="flex gap-1 items-center">
          <span className="h-1.5 w-1.5 rounded-full bg-gray-400 animate-bounce" style={{ animationDelay: "0ms" }} />
          <span className="h-1.5 w-1.5 rounded-full bg-gray-400 animate-bounce" style={{ animationDelay: "150ms" }} />
          <span className="h-1.5 w-1.5 rounded-full bg-gray-400 animate-bounce" style={{ animationDelay: "300ms" }} />
        </div>
      </div>
    </div>
  );
}

// ── Source chips ─────────────────────────────────────────────────────────
function SourceChips({ sources }: { sources: ChatSource[] }) {
  if (!sources || sources.length === 0) return null;

  const labels: Record<string, string> = {
    static_findings: "Static Analysis",
    ttp: "TTP Mapping",
    dynamic_findings: "Dynamic Analysis",
    ml_score: "ML Risk Assessment",
    llm_report: "LLM Assessment",
    virustotal: "Threat Intelligence",
  };

  return (
    <div className="mt-2 flex flex-wrap gap-1.5">
      <span className="text-xs text-gray-400">Sources:</span>
      {sources.map((s, i) => (
        <span
          key={i}
          className="rounded-full bg-indigo-50 border border-indigo-200 px-2 py-0.5 text-xs text-indigo-700"
          title={s.name ?? s.type}
        >
          {labels[s.type] ?? s.name ?? s.type}
        </span>
      ))}
    </div>
  );
}

// ── Message bubble ───────────────────────────────────────────────────────
function MessageBubble({ msg }: { msg: ChatMessage }) {
  const isUser = msg.role === "user";

  if (isUser) {
    return (
      <div className="flex items-end justify-end gap-2">
        <div className="max-w-[80%] rounded-2xl rounded-br-sm bg-indigo-600 px-4 py-2.5 text-sm text-white">
          {msg.text}
        </div>
        <UserIcon />
      </div>
    );
  }

  // Assistant message: render with basic structure detection
  const lines = msg.text.split("\n").filter(Boolean);
  const hasStructure = lines.some(
    (l) => l.match(/^\d+\./) || l.startsWith("- ") || l.startsWith("• ") || l.startsWith("#")
  );

  return (
    <div className="flex items-start gap-2">
      <AssistantIcon />
      <div className="max-w-[85%]">
        <div className="rounded-2xl rounded-tl-sm bg-gray-100 px-4 py-2.5">
          {hasStructure ? (
            <div className="space-y-1 text-sm text-gray-800">
              {lines.map((line, i) => {
                if (line.startsWith("# ")) {
                  return <p key={i} className="font-bold text-gray-900 text-base">{line.slice(2)}</p>;
                }
                if (line.startsWith("## ")) {
                  return <p key={i} className="font-semibold text-gray-800 mt-2">{line.slice(3)}</p>;
                }
                if (line.match(/^\d+\./)) {
                  return <p key={i} className="ml-3">{line}</p>;
                }
                if (line.startsWith("- ") || line.startsWith("• ")) {
                  return (
                    <p key={i} className="ml-3 flex gap-1.5">
                      <span className="shrink-0 text-gray-400">•</span>
                      <span>{line.replace(/^[-•]\s*/, "")}</span>
                    </p>
                  );
                }
                if (line.startsWith("**") && line.endsWith("**")) {
                  return <p key={i} className="font-semibold text-gray-900">{line.slice(2, -2)}</p>;
                }
                return <p key={i}>{line}</p>;
              })}
            </div>
          ) : (
            <p className="text-sm text-gray-800 leading-relaxed">{msg.text}</p>
          )}
        </div>
        {msg.sources && <SourceChips sources={msg.sources} />}
      </div>
    </div>
  );
}

// ── Empty state ──────────────────────────────────────────────────────────
function EmptyState({
  onQuestion,
}: {
  onQuestion: (q: string) => void;
}) {
  return (
    <div className="flex flex-col items-center justify-center h-full px-4 py-6 text-center">
      <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-indigo-50 text-2xl">
        🛡
      </div>
      <p className="text-sm font-semibold text-gray-700 mb-1">APK Security Assistant</p>
      <p className="text-xs text-gray-500 mb-4 max-w-xs">
        Ask questions about this APK. All answers are grounded in the analysis evidence — the assistant will not invent findings.
      </p>
      <div className="w-full max-w-md grid grid-cols-1 gap-1.5">
        {SUGGESTED_QUESTIONS.slice(0, 6).map((q) => (
          <button
            key={q}
            onClick={() => onQuestion(q)}
            className="text-left rounded-lg border border-gray-200 px-3 py-2 text-xs text-gray-700 hover:border-indigo-300 hover:bg-indigo-50 hover:text-indigo-700 transition-colors"
          >
            {q}
          </button>
        ))}
      </div>
    </div>
  );
}

// ── Notice bar ──────────────────────────────────────────────────────────
function Notice({
  notice,
  type,
}: {
  notice: string;
  type: "error" | "info" | "warning";
}) {
  const cls = {
    error: "bg-red-50 border-red-200 text-red-700",
    info: "bg-blue-50 border-blue-200 text-blue-700",
    warning: "bg-amber-50 border-amber-200 text-amber-800",
  }[type];
  return (
    <div className={`border-t px-4 py-2 text-xs ${cls}`}>{notice}</div>
  );
}

// ── Main ChatPanel ───────────────────────────────────────────────────────
export default function ChatPanel({
  submissionId,
  isPartialAnalysis = false,
}: {
  submissionId: string;
  isPartialAnalysis?: boolean;
}) {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [notice, setNotice] = useState<{
    text: string;
    type: "error" | "info" | "warning";
  } | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);

  // Auto-scroll on new messages
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const chat = useMutation({
    mutationFn: (message: string) =>
      submissionsApi.chat(submissionId, message),
    onSuccess: (res) => {
      setMessages((m) => [
        ...m,
        { role: "assistant", text: res.reply, sources: res.sources },
      ]);
      setNotice(
        res.cached
          ? { text: "This answer was served from cache.", type: "info" }
          : null
      );
    },
    onError: (err) => {
      if (err instanceof ApiRequestError) {
        if (err.status === 429) {
          setNotice({
            text: "Rate limit reached. Please wait a moment before asking another question.",
            type: "warning",
          });
        } else if (err.status === 503 || err.status === 502) {
          setNotice({
            text: "Security Assistant is temporarily unavailable. You can continue reviewing the analysis sections above.",
            type: "error",
          });
        } else if (err.status === 404) {
          setNotice({
            text: "This submission's analysis data could not be found. The assistant requires completed analysis to answer questions.",
            type: "error",
          });
        } else {
          setNotice({
            text: `Chat error (${err.status}): ${err.message ?? "The assistant encountered an error."}`,
            type: "error",
          });
        }
      } else {
        setNotice({
          text: "Chat is unavailable right now. You can continue reviewing the analysis report above.",
          type: "error",
        });
      }
    },
  });

  function sendMessage(text: string) {
    const trimmed = text.trim();
    if (!trimmed || chat.isPending) return;
    setMessages((m) => [...m, { role: "user", text: trimmed }]);
    setInput("");
    setNotice(null);
    chat.mutate(trimmed);
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    sendMessage(input);
  }

  const hasMessages = messages.length > 0;

  return (
    <div className="flex flex-col rounded-xl border border-gray-200 bg-white shadow-sm overflow-hidden h-[520px]">
      {/* Header */}
      <div className="flex items-center gap-2 border-b border-gray-100 px-4 py-3">
        <span className="text-lg">🛡</span>
        <div>
          <p className="text-sm font-semibold text-gray-900">APK Security Assistant</p>
          <p className="text-xs text-gray-500">Answers grounded in analysis evidence only</p>
        </div>
        {isPartialAnalysis && (
          <span className="ml-auto rounded-full bg-amber-100 px-2 py-0.5 text-xs font-medium text-amber-800">
            Partial analysis
          </span>
        )}
      </div>

      {/* Messages area */}
      <div className="flex-1 overflow-y-auto">
        {!hasMessages ? (
          <EmptyState onQuestion={sendMessage} />
        ) : (
          <div className="space-y-4 px-4 py-4">
            {isPartialAnalysis && messages.length === 0 && (
              <div className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800">
                ⚠ Note: Analysis for this submission is partial. The assistant will indicate when it cannot determine information due to missing analysis stages.
              </div>
            )}
            {messages.map((msg, i) => (
              <MessageBubble key={i} msg={msg} />
            ))}
            {chat.isPending && <TypingIndicator />}
            <div ref={bottomRef} />
          </div>
        )}
      </div>

      {/* Notice */}
      {notice && <Notice notice={notice.text} type={notice.type} />}

      {/* Partial analysis notice (persistent) */}
      {isPartialAnalysis && hasMessages && (
        <div className="border-t border-amber-100 bg-amber-50 px-4 py-1.5 text-xs text-amber-700">
          ⚠ Analysis is partial — the assistant may not have complete information for all questions.
        </div>
      )}

      {/* Input area */}
      <form
        onSubmit={handleSubmit}
        className="flex items-center gap-2 border-t border-gray-100 px-3 py-2.5"
      >
        <input
          id="chat-input"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              sendMessage(input);
            }
          }}
          placeholder="Ask about this APK…"
          aria-label="Chat message input"
          disabled={chat.isPending}
          className="flex-1 rounded-lg border border-gray-200 px-3 py-2 text-sm placeholder:text-gray-400 focus:outline-none focus:ring-2 focus:ring-indigo-300 disabled:opacity-50"
        />
        <button
          type="submit"
          id="chat-send-btn"
          disabled={chat.isPending || !input.trim()}
          aria-label="Send message"
          className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          <SendIcon />
        </button>
      </form>
    </div>
  );
}
