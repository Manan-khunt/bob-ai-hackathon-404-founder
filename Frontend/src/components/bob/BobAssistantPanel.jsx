import React, { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Bot,
  Send,
  Sparkles,
  X,
  User,
  Copy,
  Check,
  RotateCcw,
  ShieldAlert,
  ChevronRight,
} from 'lucide-react';
import { useAppStore } from '../../store';
import { askBobAssistant, BOB_SUGGESTED_PROMPTS } from '../../services/bob';

export default function BobAssistantPanel({ isDedicatedPage = false }) {
  const isBobOpen = useAppStore((s) => s.isBobOpen);
  const toggleBob = useAppStore((s) => s.toggleBob);

  const [messages, setMessages] = useState([
    {
      sender: 'bob',
      text: `Good day, Commander. I am **Bob**, your AI Intelligence Analyst.

I am actively synthesizing telemetry across our 8 live feeds. We are currently tracking **6 Critical Incidents**, led by **INC-1042** (APT-29 cross-domain C2 intrusion).

Select an analytical inquiry below or enter any threat query.`,
      timestamp: 'Just now',
    },
  ]);
  const [inputQuery, setInputQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const chatEndRef = useRef(null);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  const handleSend = async (queryText) => {
    const textToSend = queryText || inputQuery;
    if (!textToSend.trim() || loading) return;

    const userMsg = {
      sender: 'user',
      text: textToSend,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputQuery('');
    setLoading(true);

    try {
      const response = await askBobAssistant(textToSend);
      setMessages((prev) => [
        ...prev,
        {
          sender: 'bob',
          text: response,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        },
      ]);
    } catch {
      setMessages((prev) => [
        ...prev,
        {
          sender: 'bob',
          text: 'Autonomous intelligence analysis engine active. Reviewing active correlation graph.',
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  const panelContent = (
    <div className="flex flex-col h-full bg-slate-900 text-slate-100 select-none">
      {/* Bob Header */}
      <div className="p-4 border-b border-slate-800 bg-slate-950/70 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-sky-500/20 border border-sky-500/40 flex items-center justify-center text-sky-400">
            <Bot className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold text-white tracking-wide">BOB</h3>
              <span className="text-[9px] uppercase font-mono px-1.5 py-0.2 rounded bg-sky-500/20 text-sky-300 border border-sky-500/30">
                AI ANALYST
              </span>
            </div>
            <div className="text-2xs text-slate-400">
              Autonomous Correlation &amp; BLUF Decision Support
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {!isDedicatedPage && (
            <button
              onClick={toggleBob}
              className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>

      {/* Suggested Questions Bar */}
      <div className="p-3 bg-slate-950/40 border-b border-slate-800/80 overflow-x-auto scrollbar-none flex items-center gap-2">
        <span className="text-2xs uppercase tracking-wider text-slate-400 font-semibold shrink-0">
          Suggested:
        </span>
        {BOB_SUGGESTED_PROMPTS.slice(0, 4).map((prompt, i) => (
          <button
            key={i}
            onClick={() => handleSend(prompt)}
            disabled={loading}
            className="text-2xs px-2.5 py-1 rounded-full bg-slate-800/80 hover:bg-sky-600/20 hover:border-sky-500/40 text-slate-300 hover:text-sky-200 border border-slate-700 whitespace-nowrap transition-all shrink-0"
          >
            {prompt}
          </button>
        ))}
      </div>

      {/* Chat Messages */}
      <div className="flex-1 p-4 overflow-y-auto space-y-4">
        {messages.map((msg, idx) => {
          const isBob = msg.sender === 'bob';
          return (
            <motion.div
              key={idx}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.22 }}
              className={`flex gap-3 text-xs ${isBob ? 'justify-start' : 'justify-end'}`}
            >
              {isBob && (
                <div className="w-7 h-7 rounded-md bg-sky-500/20 border border-sky-500/40 flex items-center justify-center text-sky-400 shrink-0 mt-0.5">
                  <Bot className="w-4 h-4" />
                </div>
              )}

              <div
                className={`max-w-[85%] rounded-lg p-3.5 leading-relaxed shadow-sm ${
                  isBob
                    ? 'bg-slate-950 border border-slate-800 text-slate-200'
                    : 'bg-sky-600 text-white font-medium'
                }`}
              >
                <div className="flex items-center justify-between gap-4 mb-1 text-[10px] opacity-70">
                  <span className="font-semibold uppercase tracking-wider">
                    {isBob ? 'Bob (AI Intelligence Analyst)' : 'Commander'}
                  </span>
                  <span className="font-mono">{msg.timestamp}</span>
                </div>

                <div className="whitespace-pre-wrap text-xs space-y-2">
                  {msg.text}
                </div>
              </div>

              {!isBob && (
                <div className="w-7 h-7 rounded-md bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-300 shrink-0 mt-0.5">
                  <User className="w-4 h-4" />
                </div>
              )}
            </motion.div>
          );
        })}

        {loading && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="flex gap-3 text-xs items-center text-sky-400"
          >
            <div className="w-7 h-7 rounded-md bg-sky-500/20 border border-sky-500/40 flex items-center justify-center">
              <Bot className="w-4 h-4 animate-spin" />
            </div>
            <div className="bg-slate-950 border border-slate-800 rounded p-3 text-2xs font-mono flex items-center gap-2">
              <span>Synthesizing multi-source intelligence &amp; MITRE matrix</span>
              <span className="flex gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-sky-400 animate-bounce" />
                <span className="w-1.5 h-1.5 rounded-full bg-sky-400 animate-bounce [animation-delay:0.2s]" />
                <span className="w-1.5 h-1.5 rounded-full bg-sky-400 animate-bounce [animation-delay:0.4s]" />
              </span>
            </div>
          </motion.div>
        )}
        <div ref={chatEndRef} />
      </div>

      {/* Input Bar */}
      <div className="p-3 border-t border-slate-800 bg-slate-950/80">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSend();
          }}
          className="flex items-center gap-2"
        >
          <input
            type="text"
            placeholder="Ask Bob: e.g., 'What is our lateral movement exposure?'"
            value={inputQuery}
            onChange={(e) => setInputQuery(e.target.value)}
            disabled={loading}
            className="flex-1 bg-slate-900 border border-slate-700 rounded-md px-3 py-2 text-xs text-slate-100 placeholder:text-slate-400 focus:outline-none focus:border-sky-500"
          />
          <button
            type="submit"
            disabled={loading || !inputQuery.trim()}
            className="p-2 rounded-md bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white transition-colors"
          >
            <Send className="w-4 h-4" />
          </button>
        </form>
      </div>
    </div>
  );

  if (isDedicatedPage) {
    return <div className="h-full rounded-lg border border-slate-800 overflow-hidden">{panelContent}</div>;
  }

  return (
    <AnimatePresence>
      {isBobOpen && (
        <motion.div
          initial={{ x: '100%', opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          exit={{ x: '100%', opacity: 0 }}
          transition={{ type: 'spring', stiffness: 380, damping: 32 }}
          className="fixed inset-y-0 right-0 z-50 w-full max-w-md shadow-2xl border-l border-slate-800"
        >
          {panelContent}
        </motion.div>
      )}
    </AnimatePresence>
  );
}
